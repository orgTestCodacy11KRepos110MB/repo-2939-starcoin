// Copyright (c) The Starcoin Core Contributors
// SPDX-License-Identifier: Apache-2.0

//! This module defines all the gas parameters and formulae for instructions, along with their
//! initial values in the genesis and a mapping between the Rust representation and the on-chain
//! gas schedule.

use crate::gas_meter::EXECUTION_GAS_MULTIPLIER as MUL;
use move_binary_format::errors::PartialVMResult;
use move_core_types::gas_algebra::{
    InternalGas, InternalGasPerAbstractMemoryUnit, InternalGasPerArg, InternalGasPerByte,
};
use move_vm_types::gas::SimpleInstruction;

// see starcoin/vm/types/src/on_chain_config/genesis_gas_schedule.rs
// same order as https://github.com/starcoinorg/starcoin-framework/blob/main/sources/VMConfig.move#instruction_schedule
// modify should with impl From<VMConfig> for GasSchedule
crate::params::define_gas_parameters!(
    InstructionGasParameters,
    "instr",
    [
        [pop: InternalGas, "pop", (1 + 1)* MUL],
        [ret: InternalGas, "ret", (638 + 1) * MUL],
        [br_true: InternalGas, "br_true", (1+1)* MUL],
        [br_false: InternalGas, "br_false", (1 + 1) * MUL],
        [branch: InternalGas, "branch", (1 + 1)* MUL],
        [ld_u64: InternalGas, "ld_u64", (1 + 1)* MUL],
        [
            ld_const_per_byte: InternalGasPerByte,
            "ld_const.per_byte",
            (1 + 1) * MUL
        ],
        [ld_true: InternalGas, "ld_true", (1 + 1)* MUL],
        [ld_false: InternalGas, "ld_false", (1 + 1)* MUL],
        [
            copy_loc_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
             "copy_loc.per_abs_mem_unit",
             (1 + 1) * MUL
        ],
        [move_loc_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit, "move_loc.per_abs_mem_unit", (1 + 1)* MUL],
        [st_loc_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit, "st_loc.per_abs_mem_unit", (1 + 1)* MUL],
        [mut_borrow_loc: InternalGas, "mut_borrow_loc", (2 + 1) * MUL],
        [imm_borrow_loc: InternalGas, "imm_borrow_loc", (1 + 1)* MUL],
        [mut_borrow_field: InternalGas, "mut_borrow_field", (1 + 1)* MUL],
        [imm_borrow_field: InternalGas, "imm_borrow_field", (1 + 1)* MUL],
        [call_per_arg: InternalGasPerArg,  "call.per_arg", (1132 + 1) * MUL],
        [pack_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,  "pack.per_abs_mem_unit", (2 + 1) * MUL],
        [unpack_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit, "unpack.per_abs_mem_unit", (2 + 1) * MUL],
        [
            read_ref_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
             "read_ref.per_abs_mem_unit",
            (1 + 1) * MUL
        ],
        [write_ref_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit, "write_ref.per_abs_mem_unit", (1 + 1)* MUL],
        [add: InternalGas, "add", (1 + 1)* MUL],
        [sub: InternalGas, "sub", (1 + 1)* MUL],
        [mul: InternalGas, "mul", (1 + 1)* MUL],
        [mod_: InternalGas, "mod", (1 + 1)* MUL],
        [div: InternalGas, "div", (3 + 1) * MUL],
        [bit_or: InternalGas, "bit_or", (2 + 1) * MUL],
        [bit_and: InternalGas, "bit_and", (2 + 1) * MUL],
        [xor: InternalGas, "xor", (1 + 1)* MUL],
        [or: InternalGas, "or", (2 + 1) * MUL],
        [and: InternalGas, "and", (1 + 1)* MUL],
        [not: InternalGas, "not", (1 + 1)* MUL],
        [
            eq_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
            "eq.per_abs_mem_unit",
            (1 + 1) * MUL
        ],
        [
            neq_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
             "neq.per_abs_mem_unit",
            (1 + 1) * MUL
        ],
        // comparison
        [lt: InternalGas, "lt", (2 + 1) * MUL],
        [gt: InternalGas, "gt", (1 + 1)* MUL],
        [le: InternalGas, "le", (2 + 1) * MUL],
        [ge: InternalGas, "ge", (1 + 1)* MUL],
        [abort: InternalGas, "abort", (1 + 1)* MUL],
        // nop
        [nop: InternalGas, "nop", (1 + 1)* MUL],
        [exists_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit, "exists.per_abs_mem_unit", (41 + 1) * MUL],
        [
            mut_borrow_global_base: InternalGas,
            "mut_borrow_global.base",
            (21 + 1) * MUL
        ],
        [
            imm_borrow_global_base: InternalGas,
            "imm_borrow_global.base",
            (23 + 1) * MUL
        ],
        [move_from_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit, "move_from.per_abs_mem_unit", (459 + 1) * MUL],
        [move_to_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit, "move_to.per_abs_mem_unit", (13 + 1) * MUL],
        [freeze_ref: InternalGas, "freeze_ref", (1 + 1)* MUL],
        [shl: InternalGas, "shl", (2 + 1) * MUL],
        [shr: InternalGas, "shr", (1 + 1)* MUL],
        [ld_u8: InternalGas, "ld_u8", (1 + 1)* MUL],
        [ld_u128: InternalGas, "ld_u128", (1 + 1)* MUL],
        // casting
        [cast_u8: InternalGas, "cast_u8", (2 + 1) * MUL],
        [cast_u64: InternalGas, "cast_u64", (1 + 1)* MUL],
        [cast_u128: InternalGas, "cast_u128", (1 + 1)* MUL],
        [
            mut_borrow_field_generic: InternalGas,
            "mut_borrow_field_generic.base",
            (1 + 1)* MUL
        ],
        [
            imm_borrow_field_generic: InternalGas,
            "imm_borrow_field_generic.base",
            (1 + 1)* MUL
        ],
        [
            call_generic_per_arg: InternalGasPerArg,
            "call_generic.per_arg",
            (1 + 1) * MUL
        ],
        [
            pack_generic_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
             "pack_generic.per_abs_mem_unit",
            (2 + 1) * MUL
        ],
        [
            unpack_generic_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
             "unpack_generic.per_abs_mem_unit",
            (2 + 1) * MUL
        ],
        [
            exists_generic_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
            "exists_generic.per_abs_mem_unit",
            (34 + 1) * MUL
        ],
        [
            mut_borrow_global_generic_base: InternalGas,
            "mut_borrow_global_generic.base",
            (15 + 1) * MUL
        ],
        [
            imm_borrow_global_generic_base: InternalGas,
            "imm_borrow_global_generic.base",
            (14 + 1) * MUL
        ],
        [
            move_from_generic_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
            "move_from_generic.per_abs_mem_unit",
            (13 + 1) * MUL
        ],
        [
            move_to_generic_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
            "move_to_generic.per_abs_mem_unit",
            (27 + 1) * MUL
        ],
        [
            vec_pack_per_elem: InternalGasPerArg,
            optional "vec_pack.per_elem",
            (84 + 1) * MUL
        ],
        [vec_len_base: InternalGas, optional "vec_len.base", (98 + 1) * MUL],
        [
            vec_imm_borrow_base: InternalGas,
            optional "vec_imm_borrow.base",
            (1334 + 1) * MUL
        ],
        [
            vec_mut_borrow_base: InternalGas,
            optional "vec_mut_borrow.base",
            (1902 + 1) * MUL
        ],
        [
            vec_push_back_per_abs_mem_unit: InternalGasPerAbstractMemoryUnit,
            optional "vec_push_back.per_abs_mem_unit",
            (52 + 1) * MUL
        ],
        [
            vec_pop_back_base: InternalGas,
            optional "vec_pop_back.base",
            (227 + 1) * MUL
        ],
         [
            vec_unpack_per_expected_elem: InternalGasPerArg,
            optional "vec_unpack.per_expected_elem",
            (572 + 1) * MUL
        ],
        [vec_swap_base: InternalGas, optional "vec_swap.base", (1436 + 1) * MUL],
    ]
);

impl InstructionGasParameters {
    pub fn simple_instr_cost(&self, instr: SimpleInstruction) -> PartialVMResult<InternalGas> {
        use SimpleInstruction::*;

        Ok(match instr {
            Nop => self.nop,

            Abort => self.abort,
            Ret => self.ret,

            BrTrue => self.br_true,
            BrFalse => self.br_false,
            Branch => self.branch,

            Pop => self.pop,
            LdU8 => self.ld_u8,
            LdU64 => self.ld_u64,
            LdU128 => self.ld_u128,
            LdTrue => self.ld_true,
            LdFalse => self.ld_false,

            ImmBorrowLoc => self.imm_borrow_loc,
            MutBorrowLoc => self.mut_borrow_loc,
            ImmBorrowField => self.imm_borrow_field,
            MutBorrowField => self.mut_borrow_field,
            ImmBorrowFieldGeneric => self.imm_borrow_field_generic,
            MutBorrowFieldGeneric => self.mut_borrow_field_generic,
            FreezeRef => self.freeze_ref,

            CastU8 => self.cast_u8,
            CastU64 => self.cast_u64,
            CastU128 => self.cast_u128,

            Add => self.add,
            Sub => self.sub,
            Mul => self.mul,
            Mod => self.mod_,
            Div => self.div,

            BitOr => self.bit_or,
            BitAnd => self.bit_and,
            Xor => self.xor,
            Shl => self.shl,
            Shr => self.shr,

            Or => self.or,
            And => self.and,
            Not => self.not,

            Lt => self.lt,
            Gt => self.gt,
            Le => self.le,
            Ge => self.ge,
        })
    }
}
