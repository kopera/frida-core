[CCode(cprefix = "", cheader_filename = "windows.h")]
namespace Windows {
	public const size_t MAX_PATH;

	[SimpleType]
	[CCode (cname = "DWORD", has_type_id = false)]
	public struct ProcessId : uint32 {
	}

	[SimpleType]
	[CCode (cname = "DWORD", has_type_id = false)]
	public struct ThreadId : uint32 {
	}

	[SimpleType]
	[CCode (cname = "DWORD", has_type_id = false)]
	public struct Timeout : uint32 {
		[CCode (cname = "INFINITE")]
		public const Timeout INFINITE;
	}

	[PointerType]
	[SimpleType]
	[CCode(cname = "HANDLE", default_value = "INVALID_HANDLE_VALUE", has_type_id = false)]
	public struct Handle {
		[CCode (cname = "INVALID_HANDLE_VALUE")]
		public const Handle INVALID;

		[DestroysInstance]
		[CCode (cname = "CloseHandle")]
		public bool close ();
	}

	[CCode(cname = "HANDLE", has_type_id = false) ]
	public struct ProcessHandle : Handle {
		public ProcessId process_id {
			[CCode (cname = "GetProcessId")] get;
		}

		[CCode (cname = "ReadProcessMemory")]
		public bool read_memory(void* base_address, [CCode (array_length_type = "size_t")] uint8[] buffer, out size_t bytes_read);
		[CCode (cname = "WriteProcessMemory")]
		public bool write_memory(void* base_address, [CCode (array_length_type = "size_t")] uint8[] buffer, out size_t bytes_written);
	}

	[CCode(cname = "HANDLE", has_type_id = false) ]
	public struct ThreadHandle : Handle {
		public ThreadId thread_id {
			[CCode (cname = "GetThreadId")] get;
		}
	}

	[CCode(cname = "HANDLE", has_type_id = false) ]
	public struct FileHandle : Handle {
	}

	[SimpleType]
	[CCode (cname = "DWORD", cprefix = "ERROR_", has_type_id = false)]
	[IntegerType (rank = 7)]
	public struct Error {
		public const Error SEM_TIMEOUT;
		public const Error WAIT_TIMEOUT;

		[CCode (cname="GetLastError")]
		public static Error get_last ();
	}

	[CCode(cprefix = "", cheader_filename = "debugapi.h")]
	namespace Debug {
		[CCode (cname = "DEBUG_EVENT", has_type_id = false, destroy_function = "")]
		public struct Event {
			[CCode (cname = "dwDebugEventCode")]
			EventCode code;
			[CCode (cname = "dwProcessId")]
			ProcessId process_id;
			[CCode (cname = "dwThreadId")]
			ThreadId thread_id;
			[CCode (cname = "u.Exception")]
			ExceptionEvent.Info exception;
			[CCode (cname = "u.CreateThread")]
			CreateThreadEvent create_thread;
			[CCode (cname = "u.LoadDll")]
			LoadDllEvent load_dll;
		}

		[CCode (cname = "DWORD", has_type_id = false)]
		public enum EventCode {
			[CCode (cname = "EXCEPTION_DEBUG_EVENT")]
			EXCEPTION,
			[CCode (cname = "CREATE_THREAD_DEBUG_EVENT")]
			CREATE_THREAD,
			[CCode (cname = "CREATE_PROCESS_DEBUG_EVENT")]
			CREATE_PROCESS,
			[CCode (cname = "EXIT_THREAD_DEBUG_EVENT")]
			EXIT_THREAD,
			[CCode (cname = "EXIT_PROCESS_DEBUG_EVENT")]
			EXIT_PROCESS,
			[CCode (cname = "LOAD_DLL_DEBUG_EVENT")]
			LOAD_DLL,
			[CCode (cname = "UNLOAD_DLL_DEBUG_EVENT")]
			UNLOAD_DLL,
			[CCode (cname = "OUTPUT_DEBUG_STRING_EVENT")]
			OUTPUT_DEBUG_STRING,
			[CCode (cname = "RIP_EVENT")]
			RIP;
		}

		[CCode(cprefix = "")]
		namespace ExceptionEvent {
			[Compact]
			[CCode (cname = "EXCEPTION_DEBUG_INFO", has_type_id = false)]
			public struct Info {
				[CCode (cname = "ExceptionRecord")]
				Record record;
				[CCode (cname = "dwFirstChance")]
				bool first_chance;
			}

			[CCode (cname = "EXCEPTION_RECORD", has_type_id = false)]
			public struct Record {
				[CCode (cname = "ExceptionCode")]
				Code code;
				[CCode (cname = "ExceptionFlags")]
				Flags flags;
				[CCode (cname = "ExceptionRecord")]
				Record? origin;
				[CCode (cname = "ExceptionAddress")]
				void* address;
				[CCode (cname = "ExceptionInformation", array_length_cname = "NumberParameters")]
				ulong[] info;
			}

			[SimpleType]
			[CCode (cname = "DWORD", cprefix = "EXCEPTION_", has_type_id = false)]
			[IntegerType (rank = 7)]
			public struct Code {
				public const Code ACCESS_VIOLATION;
				public const Code ARRAY_BOUNDS_EXCEEDED;
				public const Code BREAKPOINT;
				public const Code DATATYPE_MISALIGNMENT;
				public const Code FLT_DENORMAL_OPERAND;
				public const Code FLT_DIVIDE_BY_ZERO;
				public const Code FLT_INEXACT_RESULT;
				public const Code FLT_INVALID_OPERATION;
				public const Code FLT_OVERFLOW;
				public const Code FLT_STACK_CHECK;
				public const Code FLT_UNDERFLOW;
				public const Code ILLEGAL_INSTRUCTION;
				public const Code IN_PAGE_ERROR;
				public const Code INT_DIVIDE_BY_ZERO;
				public const Code INT_OVERFLOW;
				public const Code INVALID_DISPOSITION;
				public const Code NONCONTINUABLE_EXCEPTION;
				public const Code PRIV_INSTRUCTION;
				public const Code SINGLE_STEP;
				public const Code STACK_OVERFLOW;
				[CCode (cname = "DBG_CONTROL_C")]
				public const Code DBG_CONTROL_C;
			}

			[Flags]
			[CCode (cname = "DWORD", cprefix = "EXCEPTION_")]
			public enum Flags {
				NONCONTINUABLE,
				SOFTWARE_ORIGINATE
			}

		}

		[CCode (cname = "CREATE_THREAD_DEBUG_INFO", has_type_id = false)]
		public struct CreateThreadEvent {
			[CCode (cname = "hThread")]
			ThreadHandle handle;
			[CCode (cname = "lpThreadLocalBase")]
			void* local_base;
			[CCode (cname = "lpStartAddress")]
			void* start_address;
		}

		[CCode (cname = "LOAD_DLL_DEBUG_INFO", has_type_id = false)]
		public struct LoadDllEvent {
			[CCode (cname = "hFile")]
			FileHandle handle;
			[CCode (cname = "lpBaseOfDll")]
			void* @base;
			[CCode (cname = "dwDebugInfoFileOffset")]
			uint32 debug_info_file_offset;
			[CCode (cname = "nDebugInfoSize")]
			uint32 debug_info_size;
			[CCode (cname = "lpImageName")]
			void* _image_name;
			[CCode (cname = "fUnicode")]
			ushort _unicode;
			[CCode (cname = "_vala_load_dll_debug_info_get_image_name_ptr")]
			uint8* _get_image_name_ptr (ProcessHandle process) {
				if (this._image_name == null) {
					return null;
				} else {
					uint8 address_buffer[sizeof (void*)];
					if (!process.read_memory (this._image_name, address_buffer, null)) {
						return null;
					}
					return *(uint8**)address_buffer;
				}
			}
			[CCode (cname = "_vala_load_dll_debug_info_get_image_name")]
			public string? get_image_name (ProcessHandle process) {
				uint8* image_name_ptr = this._get_image_name_ptr(process);
				if (image_name_ptr == null) return null;

				var buffer = new GLib.ByteArray ();
				if (this._unicode != 0) {
					uint8 chars[2];
					size_t chars_read;
					while (process.read_memory (image_name_ptr + buffer.len, chars, out chars_read)
							&& (chars[0] != 0 || chars[1] != 0)
							&& chars_read == 2) {
						buffer.append (chars);
					}
					buffer.append ({0, 0});

					return ((string16) buffer.data).to_string ();
				} else {
					uint8 chars[1];
					size_t chars_read;
					while (process.read_memory (image_name_ptr + buffer.len, chars, out chars_read)
							&& chars[0] != 0
							&& chars_read == 1) {
						buffer.append (chars);
					}
					buffer.append ({0});

					return (string) buffer.steal ();
				}
			}
		}

		[CCode (cname = "DWORD", cprefix = "DBG_", has_type_id = false)]
		public enum ContinueStatus {
			CONTINUE,
			EXCEPTION_NOT_HANDLED,
			REPLY_LATER
		}

		[CCode(cname = "CheckRemoteDebuggerPresent")]
		bool check_remote_debugger_present (ProcessHandle process, out bool present);

		[CCode(cname = "ContinueDebugEvent")]
		bool @continue (ProcessId process_id, ThreadId thread_id, ContinueStatus status);

		[CCode(cname = "DebugActiveProcess")]
		bool start (ProcessId process_id);

		[CCode(cname = "DebugActiveProcessStop")]
		bool stop (ProcessId process_id);

		[CCode(cname = "DebugBreakProcess")]
		bool break_process (ProcessHandle process);

		[CCode(cname = "DebugSetProcessKillOnExit")]
		bool set_process_kill_on_exit (bool kill_on_exit);

		[CCode(cname = "WaitForDebugEventEx")]
		bool wait (out Event event, Timeout timeout);
	}
}