use x86::vmx::VmFail;

use crate::prelude::*;

/// VMX operation result
pub type VmxResult<T> = core::result::Result<T, VmFail>;

/// Execute VMXON
///
/// # Safety
/// Caller must ensure the physical address points to a valid VMXON region
#[inline(always)]
pub unsafe fn vmxon(vmxon_region_pa: u64) -> VmxResult<()> {
    unsafe { x86::bits64::vmx::vmxon(vmxon_region_pa) }
}

/// Load current VMCS pointer.
#[inline(always)]
pub unsafe fn vmptrld(vmcs_region_pa: u64) -> VmxResult<()> {
    unsafe { x86::bits64::vmx::vmptrld(vmcs_region_pa) }
}

/// Execute VMXOFF
///
/// # Safety
/// Caller must ensure VMX operation is active
#[inline(always)]
pub unsafe fn vmxoff() -> VmxResult<()> {
    unsafe { x86::bits64::vmx::vmxoff() }
}

#[inline(always)]
pub unsafe fn vmclear(vmcs_region_pa: u64) -> VmxResult<()> {
    unsafe { x86::bits64::vmx::vmclear(vmcs_region_pa) }
}

#[inline(always)]
pub unsafe fn vmwrite(field: u32, value: u64) -> VmxResult<()> {
    unsafe { x86::bits64::vmx::vmwrite(field, value) }
}

#[inline(always)]
pub unsafe fn vmread(field: u32) -> VmxResult<u64> {
    unsafe { x86::bits64::vmx::vmread(field) }
}

/// Represents the types of INVEPT operations.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InveptType {
    /// Invalidate mappings associated with a single EPTP value.
    /// This type causes the logical processor to invalidate all guest-physical mappings and
    /// combined mappings associated with the EPTRTA specified in the INVEPT descriptor.
    /// Combined mappings for that EPTRTA are invalidated for all VPIDs and all PCIDs.
    SingleContext = 1,

    /// Invalidate mappings associated with all EPTP values.
    /// This type causes the logical processor to invalidate guest-physical mappings and combined mappings
    /// associated with all EPTRTAs (and, for combined mappings, for all VPIDs and PCIDs).
    AllContexts = 2,
}

/// Executes the INVEPT instruction.
///
/// # Arguments
/// * `invept_type` - The type of INVEPT operation to perform.
/// * `eptp` - The EPT pointer used for Single Context INVEPT. It should be a 64-bit value formed by
///   concatenating the EPTP's memory type (bits 2:0), page-walk length (bits 5:3), and address of the EPTP
///   (bits 63:12). For All Contexts INVEPT, this value is ignored.
///
/// # Safety
/// This function is unsafe because it involves inline assembly and direct interaction with CPU features.
#[inline(always)]
fn invept(invept_type: InveptType, eptp: u64) {
    // The INVEPT descriptor is a 128-bit value. The first 64-bits (low part) should be 0 for All-Contexts
    // and the EPTP for Single-Context. The second 64-bits (high part) should always be 0.
    let descriptor: [u64; 2] = [eptp, 0];

    unsafe {
        asm!(
        "invept {0}, [{1}]",
        in(reg) invept_type as u64,
        in(reg) &descriptor,
        options(nostack)
        );
    };
}

/// Invalidates entries in the TLB and other processor structures that cache translations derived from EPT.
///
/// This function is used to ensure that modifications to EPT entries don't cause inconsistencies due to
/// stale cached translations. It specifically invalidates mappings associated with a single EPTP value.
///
/// # Arguments
/// * `eptp` - The Extended Page Table Pointer used for Single Context INVEPT.
///            It should be a 64-bit value formed by concatenating the EPTP's memory type (bits 2:0),
///            page-walk length (bits 5:3), and address of the EPTP (bits 63:12).
#[inline(always)]
pub fn invept_single_context(eptp: u64) {
    // Perform the INVEPT operation for a single context.
    invept(InveptType::SingleContext, eptp);
}

/// Invalidates entries in the TLB and other processor structures that cache translations derived from EPT
/// for all EPTP values.
///
/// This function is used to invalidate guest-physical mappings and combined mappings associated with all
/// EPT Pointer Table Roots (EPTRTAs) and, for combined mappings, for all VPIDs and PCIDs.
#[inline(always)]
pub fn invept_all_contexts() {
    // Perform the INVEPT operation for all contexts.
    // The EPT pointer is irrelevant for this type of operation and is thus set to 0.
    invept(InveptType::AllContexts, 0);
}

/// Represents the types of INVVPID operations.
#[repr(u64)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum InvvpidType {
    /// Invalidate mappings associated with a specific linear address and VPID.
    /// This type invalidates mappings—except global translations—associated with the specified VPID
    /// that would be used to translate the specified linear address.
    IndividualAddress = 0,

    /// Invalidate mappings associated with a specific VPID.
    /// This type invalidates all mappings—except global translations—associated with the specified VPID.
    SingleContext = 1,

    /// Invalidate mappings—including global translations—associated with all VPIDs.
    /// This type invalidates all mappings for all VPIDs.
    AllContextsIncludingGlobals = 2,

    /// Invalidate mappings associated with all VPIDs except global translations.
    /// This type invalidates all mappings except for global translations for all VPIDs.
    AllContexts = 3,
}

/// Represents an INVVPID descriptor.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvvpidDescriptor {
    /// Virtual Processor Identifier
    pub vpid: u16,
    /// Reserved fields (must be zero)
    pub reserved: [u16; 3],
    /// Linear address (used only for IndividualAddress type)
    pub linear_address: u64,
}

/// Performs the INVVPID instruction.
///
/// # Arguments
/// * `invvpid_type` - The type of invalidation to perform.
/// * `descriptor` - The INVVPID descriptor.
#[inline(always)]
fn invvpid(invvpid_type: InvvpidType, descriptor: &InvvpidDescriptor) {
    let descriptor_ptr = descriptor as *const _ as u64;
    unsafe {
        core::arch::asm!(
        "invvpid {0}, [{1}]",
        in(reg) invvpid_type as u64,
        in(reg) descriptor_ptr,
        options(nostack)
        );
    }
}

/// Invalidates TLB and paging-structure cache entries associated with a specific linear address and VPID.
///
/// # Arguments
/// * `vpid` - Virtual Processor Identifier.
/// * `linear_address` - Specific linear address whose mappings are to be invalidated.
#[inline(always)]
pub fn invvpid_individual_address(vpid: u16, linear_address: u64) {
    let descriptor = InvvpidDescriptor {
        vpid,
        reserved: [0; 3], // Reserved fields, must be zero
        linear_address,
    };
    // Perform the INVVPID operation for an individual address.
    invvpid(InvvpidType::IndividualAddress, &descriptor);
}

/// Invalidates TLB and paging-structure cache entries associated with a specific VPID.
///
/// # Arguments
/// * `vpid` - Virtual Processor Identifier.
#[inline(always)]
pub fn invvpid_single_context(vpid: u16) {
    let descriptor = InvvpidDescriptor {
        vpid,              // VPID of the target context
        reserved: [0; 3],  // Reserved fields, must be zero
        linear_address: 0, // Irrelevant for SingleContext, but required for struct completeness
    };
    // Perform the INVVPID operation for a single context.
    invvpid(InvvpidType::SingleContext, &descriptor);
}

/// Invalidates TLB and paging-structure cache entries for all VPIDs.
///
/// This operation ignores the descriptor fields as they are irrelevant for the AllContexts type.
#[inline(always)]
pub fn invvpid_all_contexts() {
    let descriptor = InvvpidDescriptor {
        vpid: 0,           // Irrelevant for AllContexts
        reserved: [0; 3],  // Reserved fields, must be zero
        linear_address: 0, // Irrelevant for AllContexts
    };
    // Perform the INVVPID operation for all contexts.
    invvpid(InvvpidType::AllContexts, &descriptor);
}
