use crate::access_path_cache::AccessPathCache;
use crate::move_vm_ext::MoveResolverExt;
use move_core_types::account_address::AccountAddress;
use move_core_types::effects::{ChangeSet as MoveChangeSet, Event as MoveEvent};
use move_core_types::language_storage::ModuleId;
use move_core_types::vm_status::{StatusCode, VMStatus};
use move_table_extension::{NativeTableContext, TableChange, TableChangeSet};
use move_vm_runtime::session::Session;
use serde::{Deserialize, Serialize};
use starcoin_crypto::hash::{CryptoHash, CryptoHasher, PlainCryptoHash};
use starcoin_crypto::HashValue;
use starcoin_vm_types::block_metadata::BlockMetadata;
use starcoin_vm_types::contract_event::ContractEvent;
use starcoin_vm_types::errors::{Location, VMResult};
use starcoin_vm_types::event::EventKey;
use starcoin_vm_types::state_store::state_key::StateKey;
use starcoin_vm_types::transaction::SignatureCheckedTransaction;
use starcoin_vm_types::transaction_metadata::TransactionMetadata;
use starcoin_vm_types::write_set::{WriteOp, WriteSet, WriteSetMut};
use std::ops::{Deref, DerefMut};

#[derive(CryptoHasher, Deserialize, Serialize, CryptoHash)]
pub enum SessionId {
    Txn {
        sender: AccountAddress,
        sequence_number: u64,
    },
    BlockMeta {
        // block id
        id: HashValue,
    },
    Genesis {
        // id to identify this specific genesis build
        id: HashValue,
    },
    // For those runs that are not a transaction and the output of which won't be committed.
    Void,
}

impl SessionId {
    pub fn txn(txn: &SignatureCheckedTransaction) -> Self {
        Self::Txn {
            sender: txn.sender(),
            sequence_number: txn.sequence_number(),
        }
    }

    pub fn txn_meta(txn_data: &TransactionMetadata) -> Self {
        Self::Txn {
            sender: txn_data.sender,
            sequence_number: txn_data.sequence_number,
        }
    }

    pub fn genesis(id: HashValue) -> Self {
        Self::Genesis { id }
    }

    pub fn block_meta(block_meta: &BlockMetadata) -> Self {
        Self::BlockMeta {
            id: block_meta.id(),
        }
    }

    pub fn void() -> Self {
        Self::Void
    }

    pub fn as_uuid(&self) -> u128 {
        u128::from_be_bytes(
            // XXX FIXME YSG
            self.crypto_hash().as_ref()[..16]
                .try_into()
                .expect("Slice to array conversion failed."),
        )
    }
}

pub struct SessionExt<'r, 'l, S> {
    inner: Session<'r, 'l, S>,
}

impl<'r, 'l, S> SessionExt<'r, 'l, S>
where
    S: MoveResolverExt,
{
    pub fn new(inner: Session<'r, 'l, S>) -> Self {
        Self { inner }
    }

    pub fn finish(self) -> VMResult<SessionOutput> {
        let (change_set, events, mut extensions) = self.inner.finish_with_extensions()?;
        let table_context: NativeTableContext = extensions.remove();
        let table_change_set = table_context
            .into_change_set()
            .map_err(|e| e.finish(Location::Undefined))?;

        Ok(SessionOutput {
            change_set,
            events,
            table_change_set,
        })
    }
}

impl<'r, 'l, S> Deref for SessionExt<'r, 'l, S> {
    type Target = Session<'r, 'l, S>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<'r, 'l, S> DerefMut for SessionExt<'r, 'l, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

pub struct SessionOutput {
    pub change_set: MoveChangeSet,
    pub events: Vec<MoveEvent>,
    pub table_change_set: TableChangeSet,
}

impl SessionOutput {
    pub fn into_change_set<C: AccessPathCache>(
        self,
        ap_cache: &mut C,
    ) -> Result<(WriteSet, Vec<ContractEvent>), VMStatus> {
        let Self {
            change_set,
            events,
            table_change_set,
        } = self;

        let mut write_set_mut = WriteSetMut::new(Vec::new());
        for (addr, account_changeset) in change_set.into_inner() {
            let (modules, resources) = account_changeset.into_inner();
            for (struct_tag, blob_opt) in resources {
                let ap = ap_cache.get_resource_path(addr, struct_tag);
                let op = match blob_opt {
                    None => WriteOp::Deletion,
                    Some(blob) => WriteOp::Value(blob),
                };
                write_set_mut.push((StateKey::AccessPath(ap), op))
            }

            for (name, blob_opt) in modules {
                let ap = ap_cache.get_module_path(ModuleId::new(addr, name));
                let op = match blob_opt {
                    None => WriteOp::Deletion,
                    Some(blob) => WriteOp::Value(blob),
                };

                write_set_mut.push((StateKey::AccessPath(ap), op))
            }
        }

        for (handle, change) in table_change_set.changes {
            for (key, value_opt) in change.entries {
                let state_key = StateKey::table_item(handle.0, key);
                if let Some(bytes) = value_opt {
                    write_set_mut.push((state_key, WriteOp::Value(bytes)))
                } else {
                    write_set_mut.push((state_key, WriteOp::Deletion))
                }
            }
        }

        let write_set = write_set_mut
            .freeze()
            .map_err(|_| VMStatus::Error(StatusCode::DATA_FORMAT_ERROR))?;

        let events = events
            .into_iter()
            .map(|(guid, seq_num, ty_tag, blob)| {
                let key = EventKey::try_from(guid.as_slice())
                    .map_err(|_| VMStatus::Error(StatusCode::EVENT_KEY_MISMATCH))?;
                Ok(ContractEvent::new(key, seq_num, ty_tag, blob))
            })
            .collect::<Result<Vec<_>, VMStatus>>()?;

        Ok((write_set, events))
    }

    pub fn squash(&mut self, other: Self) -> Result<(), VMStatus> {
        self.change_set
            .squash(other.change_set)
            .map_err(|_| VMStatus::Error(StatusCode::DATA_FORMAT_ERROR))?;
        self.events.extend(other.events.into_iter());

        // Squash the table changes
        self.table_change_set
            .new_tables
            .extend(other.table_change_set.new_tables);
        for removed_table in &self.table_change_set.removed_tables {
            self.table_change_set.new_tables.remove(removed_table);
        }
        // There's chance that a table is added in `self`, and an item is added to that table in
        // `self`, and later the item is deleted in `other`, netting to a NOOP for that item,
        // but this is an tricky edge case that we don't expect to happen too much, it doesn't hurt
        // too much to just keep the deletion. It's safe as long as we do it that way consistently.
        self.table_change_set
            .removed_tables
            .extend(other.table_change_set.removed_tables.into_iter());
        for (handle, changes) in other.table_change_set.changes.into_iter() {
            let my_changes = self
                .table_change_set
                .changes
                .entry(handle)
                .or_insert(TableChange {
                    entries: Default::default(),
                });
            my_changes.entries.extend(changes.entries.into_iter());
        }
        Ok(())
    }
}
