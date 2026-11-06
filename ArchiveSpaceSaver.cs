// Archive Space Saver
//
// Extracts a single .rar or .zip using the 7z.dll from your installed 7-Zip and, while it works, hands
// the disk space of the already-read part of the archive back to Windows (NTFS sparse "punch hole"), so
// extracting a 50 GB .rar needs ~50 GB free instead of ~100 GB. (Below, ".rar" means either kind.)
// ZIP items report where they sit in the file, so for ZIP the pre-flight check also proves they are
// stored in extraction order before anything is freed.
//
// Why 7z.dll in-process instead of running UnRAR/7z.exe: those programs refuse to open a file that
// another program holds open for writing, so nothing outside could free space in the .rar while they
// read it. Here the app itself opens the .rar once and feeds 7-Zip's engine from that one handle,
// which also tells us *exactly* how far extraction has read.
//
// How it stays safe:
//   * Only touches the .rar you pick and the (empty/new) folder you extract into. No registry, no
//     settings files, no services, no admin rights, nothing installed.
//   * Frees only data far behind the read position (Margin), never the last TailGuard bytes, and
//     refuses to start unless there is provably enough free space for the whole extraction.
//   * If extraction ever tries to read data it already freed, it stops with a clear message instead
//     of producing corrupt files.
//   * Refuses damaged, cut-short, still-downloading or partly used-up archives before touching them, and
//     (optionally, on by default) tests every file before anything is touched.
//   * If the drive fills up mid-run, waits for space instead of failing; deletes the .rar only if every
//     file the check counted was extracted OK.
//   * Never overwrites: the extract folder must be empty/new. Every name is checked before anything is
//     touched: characters Windows doesn't allow become '_' (like 7-Zip), ".." and clashing names are refused.
//   * Only frees space when the .rar and the extract folder share a drive; otherwise the .rar is left alone.
//
// Build: see build.cmd (C# 5 / .NET Framework 4, x64, nothing to install).

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Windows.Forms;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;

namespace ArchiveSpaceSaver
{
    // ------------------------------------------------------------------------------------------
    // Win32 interop
    // ------------------------------------------------------------------------------------------
    static class NativeMethods
    {
        public const uint GENERIC_READ = 0x80000000;
        public const uint GENERIC_WRITE = 0x40000000;
        public const uint FILE_WRITE_ATTRIBUTES = 0x100;
        public const uint FILE_SHARE_READ = 1;
        public const uint FILE_SHARE_ALL = 7;
        public const uint CREATE_NEW = 1;
        public const uint OPEN_EXISTING = 3;
        public const uint FILE_ATTRIBUTE_NORMAL = 0x80;
        public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000; // needed to open a folder
        public const int FileAllocationInfo = 5;
        public const int ERROR_HANDLE_DISK_FULL = 39, ERROR_DISK_FULL = 112;
        public const uint FSCTL_SET_SPARSE = 0x000900C4;
        public const uint FSCTL_SET_ZERO_DATA = 0x000980C8;
        public const uint FILE_SUPPORTS_SPARSE_FILES = 0x40;
        public const uint INVALID_FILE_ATTRIBUTES = 0xFFFFFFFF;

        [StructLayout(LayoutKind.Sequential)]
        public struct FILE_ZERO_DATA_INFORMATION
        {
            public long FileOffset;
            public long BeyondFinalZero;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(string name, uint access, uint share, IntPtr security,
            uint disposition, uint flags, IntPtr template);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
        public static extern bool DeviceIoControlNoBuffer(SafeFileHandle h, uint code, IntPtr inBuf, uint inSize,
            IntPtr outBuf, uint outSize, out uint returned, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "DeviceIoControl")]
        public static extern bool DeviceIoControlZeroData(SafeFileHandle h, uint code,
            ref FILE_ZERO_DATA_INFORMATION inBuf, uint inSize, IntPtr outBuf, uint outSize, out uint returned,
            IntPtr overlapped);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetDiskFreeSpaceExW(string dir, out ulong freeAvailable, out ulong total,
            out ulong totalFree);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetVolumePathNameW(string path, StringBuilder buffer, uint length);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool GetVolumeInformationW(string root, StringBuilder volName, uint volNameSize,
            out uint serial, out uint maxComponent, out uint flags, StringBuilder fsName, uint fsNameSize);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetCompressedFileSizeW(string path, out uint high);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern uint GetFileAttributesW(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateDirectoryW(string path, IntPtr security);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFileTime(SafeFileHandle h, IntPtr creation, IntPtr access, ref long write);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool WriteFile(SafeFileHandle h, IntPtr buffer, uint count, out uint written, IntPtr overlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetFileInformationByHandle(SafeFileHandle h, int infoClass, ref long info, uint size);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryW(string path);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr module, string name);

        [DllImport("ole32.dll")]
        public static extern int PropVariantClear(IntPtr pv);
    }

    // ------------------------------------------------------------------------------------------
    // 7-Zip COM interfaces (7z.dll). Only what is needed, in the exact vtable order.
    // ------------------------------------------------------------------------------------------
    [ComImport, Guid("23170F69-40C1-278A-0000-000300030000"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IInStream
    {
        [PreserveSig] int Read(IntPtr data, uint size, IntPtr processed);
        [PreserveSig] int Seek(long offset, uint origin, IntPtr newPosition);
    }

    [ComImport, Guid("23170F69-40C1-278A-0000-000300020000"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface ISequentialOutStream
    {
        [PreserveSig] int Write(IntPtr data, uint size, IntPtr processed);
    }

    [ComImport, Guid("23170F69-40C1-278A-0000-000600200000"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IArchiveExtractCallback
    {
        // IProgress
        [PreserveSig] int SetTotal(ulong total);
        [PreserveSig] int SetCompleted(IntPtr completeValue);
        // IArchiveExtractCallback
        [PreserveSig] int GetStream(uint index, [MarshalAs(UnmanagedType.Interface)] out ISequentialOutStream outStream, int askExtractMode);
        [PreserveSig] int PrepareOperation(int askExtractMode);
        [PreserveSig] int SetOperationResult(int operationResult);
    }

    [ComImport, Guid("23170F69-40C1-278A-0000-000600600000"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    interface IInArchive
    {
        [PreserveSig] int Open([MarshalAs(UnmanagedType.Interface)] IInStream stream, IntPtr maxCheckStartPosition, IntPtr openCallback);
        [PreserveSig] int Close();
        [PreserveSig] int GetNumberOfItems(out uint numItems);
        [PreserveSig] int GetProperty(uint index, int propId, IntPtr value);
        [PreserveSig] int Extract(IntPtr indices, uint numItems, int testMode, [MarshalAs(UnmanagedType.Interface)] IArchiveExtractCallback callback);
        [PreserveSig] int GetArchiveProperty(int propId, IntPtr value);
    }

    sealed class SevenZipLib
    {
        const int kpidPath = 3, kpidIsDir = 6, kpidSize = 7, kpidPackSize = 8, kpidMTime = 12, kpidSolid = 13,
                  kpidEncrypted = 15, kpidSplitBefore = 16, kpidSplitAfter = 17, kpidOffset = 36,
                  kpidError = 55, kpidErrorFlags = 71, kpidWarningFlags = 72, kpidWarning = 73;
        public const int E_ABORT = unchecked((int)0x80004004);
        public const int E_FAIL = unchecked((int)0x80004005);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate int CreateObjectFn(ref Guid clsid, ref Guid iid, out IntPtr obj);

        CreateObjectFn create;

        public static SevenZipLib Load(string dllPath, out string error)
        {
            error = null;
            IntPtr module = NativeMethods.LoadLibraryW(dllPath);
            if (module == IntPtr.Zero)
            {
                error = "Couldn't load " + dllPath + " (" + new Win32Exception(Marshal.GetLastWin32Error()).Message +
                        "). It needs to be the 64-bit 7z.dll from 7-Zip.";
                return null;
            }
            IntPtr fn = NativeMethods.GetProcAddress(module, "CreateObject");
            if (fn == IntPtr.Zero) { error = "That file isn't a 7-Zip 7z.dll (no CreateObject)."; return null; }
            SevenZipLib lib = new SevenZipLib();
            lib.create = (CreateObjectFn)Marshal.GetDelegateForFunctionPointer(fn, typeof(CreateObjectFn));
            return lib;
        }

        // Picks the handler by looking at the file's signature (RAR5 = Rar!\x1A\x07\x01\0, RAR4 = Rar!\x1A\x07\0,
        // ZIP = PK\x03\x04), so a file is read as what it really is whatever it's called.
        public IInArchive CreateHandler(byte[] header, out string error)
        {
            error = null;
            byte formatId;
            if (header.Length >= 8 && header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 && header[3] == 0x21 &&
                header[4] == 0x1A && header[5] == 0x07 && header[6] == 0x01 && header[7] == 0x00) formatId = 0xCC; // Rar5
            else if (header.Length >= 7 && header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 && header[3] == 0x21 &&
                header[4] == 0x1A && header[5] == 0x07 && header[6] == 0x00) formatId = 0x03; // Rar
            else if (header.Length >= 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04) formatId = 0x01; // Zip
            else { error = "This file doesn't start like a RAR or ZIP archive (damaged, or not finished downloading?)."; return null; }

            Guid clsid = new Guid(0x23170F69, 0x40C1, 0x278A, 0x10, 0x00, 0x00, 0x01, 0x10, formatId, 0x00, 0x00);
            Guid iid = typeof(IInArchive).GUID;
            IntPtr obj;
            int hr = create(ref clsid, ref iid, out obj);
            if (hr != 0 || obj == IntPtr.Zero)
            {
                error = "This 7-Zip can't read this kind of archive (error 0x" + hr.ToString("X8", CultureInfo.InvariantCulture) + ").";
                return null;
            }
            try { return (IInArchive)Marshal.GetObjectForIUnknown(obj); }
            finally { Marshal.Release(obj); }
        }

        // ---- PROPVARIANT reading
        static object GetProp(IInArchive a, uint index, int propId)
        {
            return ReadProp(delegate(IntPtr pv) { return a.GetProperty(index, propId, pv); });
        }

        static object GetArcProp(IInArchive a, int propId)
        {
            return ReadProp(delegate(IntPtr pv) { return a.GetArchiveProperty(propId, pv); });
        }

        static object ReadProp(Func<IntPtr, int> get)
        {
            IntPtr pv = Marshal.AllocCoTaskMem(24);
            try
            {
                Marshal.WriteInt64(pv, 0, 0); Marshal.WriteInt64(pv, 8, 0); Marshal.WriteInt64(pv, 16, 0);
                if (get(pv) != 0) return null;
                short vt = Marshal.ReadInt16(pv, 0);
                switch (vt)
                {
                    case 8: // VT_BSTR
                        IntPtr b = Marshal.ReadIntPtr(pv, 8);
                        return b == IntPtr.Zero ? null : Marshal.PtrToStringBSTR(b);
                    case 11: return Marshal.ReadInt16(pv, 8) != 0; // VT_BOOL
                    case 18: return (ulong)(ushort)Marshal.ReadInt16(pv, 8);
                    case 19: return (ulong)(uint)Marshal.ReadInt32(pv, 8);
                    case 20: case 21: return (ulong)Marshal.ReadInt64(pv, 8);
                    case 64: return Marshal.ReadInt64(pv, 8); // VT_FILETIME (long)
                    default: return null;
                }
            }
            finally { NativeMethods.PropVariantClear(pv); Marshal.FreeCoTaskMem(pv); }
        }

        public static string PropPath(IInArchive a, uint i) { return GetProp(a, i, kpidPath) as string; }
        public static bool PropIsDir(IInArchive a, uint i) { object o = GetProp(a, i, kpidIsDir); return o is bool && (bool)o; }
        public static bool PropFlag(IInArchive a, uint i, int id) { object o = GetProp(a, i, id); return o is bool && (bool)o; }
        public static long PropSize(IInArchive a, uint i) { object o = GetProp(a, i, kpidSize); return o is ulong ? (long)(ulong)o : -1; }
        public static long PropPackSize(IInArchive a, uint i) { object o = GetProp(a, i, kpidPackSize); return o is ulong ? (long)(ulong)o : -1; }
        public static long PropMTime(IInArchive a, uint i) { object o = GetProp(a, i, kpidMTime); return o is long ? (long)o : 0; }
        // Where the item's header starts in the archive file. ZIP reports it, RAR doesn't (-1).
        public static long PropOffset(IInArchive a, uint i) { object o = GetProp(a, i, kpidOffset); return o is ulong ? (long)(ulong)o : -1; }
        public static bool PropSolid(IInArchive a, uint i) { return PropFlag(a, i, kpidSolid); }
        public static bool PropEncrypted(IInArchive a, uint i) { return PropFlag(a, i, kpidEncrypted); }
        public static bool PropSplit(IInArchive a, uint i) { return PropFlag(a, i, kpidSplitBefore) || PropFlag(a, i, kpidSplitAfter); }

        static readonly string[] FlagNames = { "not a valid archive", "damaged headers", "encrypted headers can't be read",
            "start of the archive is missing", "start of the archive not confirmed", "unexpected end of archive",
            "extra data after the end", "unsupported compression method", "unsupported feature", "data error", "checksum error" };

        // Problems 7-Zip noticed while opening. It opens a damaged or cut-short archive as far as it can instead of
        // failing, so these flags are the only sign. Returns null when there are none.
        public static string ArchiveDamage(IInArchive a)
        {
            object err = GetArcProp(a, kpidErrorFlags), warn = GetArcProp(a, kpidWarningFlags);
            ulong flags = (err is ulong ? (ulong)err : 0) | (warn is ulong ? (ulong)warn : 0);
            List<string> found = new List<string>();
            for (int b = 0; b < FlagNames.Length; b++) if ((flags & (1UL << b)) != 0) found.Add(FlagNames[b]);
            if ((flags >> FlagNames.Length) != 0) found.Add("problem flags 0x" + flags.ToString("X", CultureInfo.InvariantCulture));
            string text = GetArcProp(a, kpidError) as string;
            if (!string.IsNullOrEmpty(text)) found.Add(text);
            text = GetArcProp(a, kpidWarning) as string;
            if (!string.IsNullOrEmpty(text)) found.Add(text);
            return found.Count == 0 ? null : string.Join(", ", found.ToArray());
        }

        // What 7-Zip's per-file result codes mean.
        public static string DescribeResult(int r)
        {
            switch (r)
            {
                case 1: return "compression method not supported";
                case 2: return "data error (damaged or incomplete archive)";
                case 3: return "checksum failed (damaged or incomplete archive)";
                case 4: return "data not available";
                case 5: return "unexpected end of archive (not finished downloading?)";
                case 6: return "extra data after the end of the file";
                case 7: return "not an archive";
                case 8: return "damaged headers";
                case 9: return "wrong password";
                default: return "error " + r;
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------------------------------
    static class Util
    {
        public const long MiB = 1024L * 1024L;
        public const long GiB = 1024L * 1024L * 1024L;

        public static string Size(long bytes)
        {
            if (bytes < 0) bytes = 0;
            double gb = bytes / (double)GiB;
            if (gb >= 1.0) return gb.ToString("0.00", CultureInfo.InvariantCulture) + " GB";
            return (bytes / (double)MiB).ToString("0.0", CultureInfo.InvariantCulture) + " MB";
        }

        // ".rar" or ".zip", for messages ("the .zip is used up...").
        public static string ArcName(string path)
        {
            string ext = Path.GetExtension(path ?? "").ToLowerInvariant();
            return ext == ".rar" || ext == ".zip" ? ext : "archive";
        }

        public static string Duration(TimeSpan t)
        {
            return string.Format(CultureInfo.InvariantCulture, "{0}:{1:00}:{2:00}", (int)t.TotalHours, t.Minutes, t.Seconds);
        }

        public static string VolumeRoot(string path)
        {
            StringBuilder sb = new StringBuilder(1024);
            if (!NativeMethods.GetVolumePathNameW(path, sb, (uint)sb.Capacity)) return null;
            return sb.ToString();
        }

        public static bool SupportsSparse(string root)
        {
            uint serial, maxc, flags;
            StringBuilder vol = new StringBuilder(261), fs = new StringBuilder(261);
            if (!NativeMethods.GetVolumeInformationW(root, vol, 261, out serial, out maxc, out flags, fs, 261))
                return false;
            return (flags & NativeMethods.FILE_SUPPORTS_SPARSE_FILES) != 0;
        }

        public static long FreeSpace(string existingDir)
        {
            ulong avail, total, free;
            if (!NativeMethods.GetDiskFreeSpaceExW(existingDir, out avail, out total, out free)) return -1;
            return (long)avail;
        }

        // Bytes actually occupying disk space for this file (shrinks as we punch holes).
        public static long AllocatedSize(string path)
        {
            uint high;
            uint low = NativeMethods.GetCompressedFileSizeW(path, out high);
            if (low == 0xFFFFFFFF && Marshal.GetLastWin32Error() != 0) return -1;
            return ((long)high << 32) | low;
        }

        public static string NearestExistingDirectory(string path)
        {
            string p = path;
            while (!string.IsNullOrEmpty(p) && !Directory.Exists(p)) p = Path.GetDirectoryName(p);
            return p;
        }

        // \\?\ form so paths over 260 characters work.
        public static string LongPath(string full)
        {
            if (full.StartsWith(@"\\?\", StringComparison.Ordinal)) return full;
            if (full.StartsWith(@"\\", StringComparison.Ordinal)) return @"\\?\UNC\" + full.Substring(2);
            return @"\\?\" + full;
        }

        // Path.GetDirectoryName throws on paths over 260 characters in .NET Framework's default mode, so split by hand.
        public static string ParentOf(string full)
        {
            int k = full.LastIndexOf('\\');
            return k > 0 ? full.Substring(0, k) : null;
        }

        public static void EnsureDirectory(string full)
        {
            string lp = LongPath(full);
            uint attr = NativeMethods.GetFileAttributesW(lp);
            if (attr != NativeMethods.INVALID_FILE_ATTRIBUTES)
            {
                if ((attr & 0x10) != 0) return;
                throw new IOException("A file is in the way of the folder: " + full);
            }
            string parent = ParentOf(full);
            if (parent != null && parent.Length > 3) EnsureDirectory(parent);
            if (!NativeMethods.CreateDirectoryW(lp, IntPtr.Zero))
            {
                int err = Marshal.GetLastWin32Error();
                if (err != 183) throw new IOException("Couldn't create folder " + full + ": " + new Win32Exception(err).Message);
            }
        }

        public const long ReserveMin = 16 * MiB;   // smaller files aren't worth reserving
        public const long ReserveSpare = 2 * GiB;  // only reserve when at least this much stays free afterwards

        // Reserves a big file's full size before it's written, so Windows can lay it out in one piece. Only when the
        // drive has room to spare: reserving early would eat into the space the .rar gives back as it goes, which is
        // the whole point. Best effort; the file is written either way.
        public static void TryReserve(SafeFileHandle h, long size, string dir)
        {
            if (size < ReserveMin) return;
            long free = FreeSpace(dir);
            if (free < 0 || free - size < ReserveSpare) return;
            NativeMethods.SetFileInformationByHandle(h, NativeMethods.FileAllocationInfo, ref size, 8);
        }

        public static void SetFolderTime(string full, long fileTime)
        {
            if (fileTime <= 0) return;
            using (SafeFileHandle h = NativeMethods.CreateFileW(LongPath(full), NativeMethods.FILE_WRITE_ATTRIBUTES, NativeMethods.FILE_SHARE_ALL,
                       IntPtr.Zero, NativeMethods.OPEN_EXISTING, NativeMethods.FILE_FLAG_BACKUP_SEMANTICS, IntPtr.Zero))
            {
                if (!h.IsInvalid) NativeMethods.SetFileTime(h, IntPtr.Zero, IntPtr.Zero, ref fileTime);
            }
        }

        // Finds the 64-bit 7z.dll: wherever 7-Zip's installer recorded it went (read from the registry; nothing is
        // written), then the default folder.
        public static string FindSevenZipDll()
        {
            List<string> dirs = new List<string>();
            foreach (RegistryHive hive in new RegistryHive[] { RegistryHive.CurrentUser, RegistryHive.LocalMachine })
            {
                try
                {
                    using (RegistryKey hiveKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                    using (RegistryKey k = hiveKey.OpenSubKey(@"Software\7-Zip"))
                    {
                        if (k == null) continue;
                        foreach (string name in new string[] { "Path64", "Path" })
                        {
                            string dir = k.GetValue(name) as string;
                            if (!string.IsNullOrEmpty(dir)) dirs.Add(dir.Trim().Trim('"'));
                        }
                    }
                }
                catch (Exception) { } // can't read it: fall back to the default folders
            }
            foreach (string pf in new string[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                                 Environment.GetEnvironmentVariable("ProgramW6432") })
                if (!string.IsNullOrEmpty(pf)) dirs.Add(Path.Combine(pf, "7-Zip"));

            foreach (string dir in dirs)
            {
                string dll;
                try { dll = Path.Combine(dir, "7z.dll"); }
                catch (ArgumentException) { continue; }
                if (File.Exists(dll) && Is64BitDll(dll)) return dll;
            }
            return "";
        }

        // This app is 64-bit, so it can only load a 64-bit 7z.dll.
        public static bool Is64BitDll(string path)
        {
            try
            {
                using (FileStream f = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BinaryReader r = new BinaryReader(f))
                {
                    f.Position = 0x3C;
                    f.Position = r.ReadInt32();
                    return r.ReadUInt32() == 0x00004550 && r.ReadUInt16() == 0x8664; // "PE\0\0", x64
                }
            }
            catch (Exception) { return false; }
        }

        static readonly Regex Reserved = new Regex(@"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", RegexOptions.IgnoreCase);
        static readonly char[] BadChars = { '<', '>', ':', '"', '|', '?', '*' };

        // Turns a path stored in the archive into a relative path that is safe to create under the extract folder.
        // Like 7-Zip: characters Windows doesn't allow (and a trailing space or dot) become '_', reserved device
        // names get a '_' in front, a leading '\' or drive letter can't escape the folder. "renamed" says whether
        // anything had to change. Fails (with why) only for names that can't be made safe: empty, ".." or too long.
        // The pre-flight check and the extraction both use this, so they always agree on every name.
        public static bool TrySafeRelativePath(string raw, out string rel, out bool renamed, out string why)
        {
            rel = null; why = null; renamed = false;
            if (string.IsNullOrEmpty(raw)) { why = "empty name"; return false; }
            List<string> parts = new List<string>();
            foreach (string seg in raw.Replace('/', '\\').Split('\\'))
            {
                if (seg.Length == 0 || seg == ".") continue;
                if (seg == "..") { why = "path goes up a folder (\"..\")"; return false; }
                char[] c = seg.ToCharArray();
                for (int i = 0; i < c.Length; i++)
                    if (c[i] < ' ' || Array.IndexOf(BadChars, c[i]) >= 0) { c[i] = '_'; renamed = true; }
                if (c[c.Length - 1] == ' ' || c[c.Length - 1] == '.') { c[c.Length - 1] = '_'; renamed = true; }
                string s = new string(c);
                if (Reserved.IsMatch(s)) { s = "_" + s; renamed = true; }
                if (s.Length > 255) { why = "a name is longer than Windows allows (255 characters)"; return false; }
                parts.Add(s);
            }
            if (parts.Count == 0) { why = "empty name"; return false; }
            rel = string.Join("\\", parts.ToArray());
            return true;
        }
    }

    // ------------------------------------------------------------------------------------------
    // Pre-flight check result
    // ------------------------------------------------------------------------------------------
    sealed class Preflight
    {
        public string Error;
        public string Archive, Dest, SevenZipDll;
        public long ArchiveBytes, UnpackedBytes, PeakExtra, NeededFree, FreeBytes;
        public int FileCount;
        public bool SameVolume, Solid;
        public string DestRoot;
        public int RenamedCount;         // names that need fixing to be valid on Windows
        public string RenamedExample;
    }

    enum RunPhase { Opening, Testing, Extracting, Finishing }

    sealed class RunResult
    {
        public bool Success;
        public bool Cancelled;
        public bool StartFailed;
        public bool TestFailed;          // the test pass found problems; nothing was extracted or changed
        public bool ArchiveDeleted;
        public bool ArchiveIntact;       // no space was taken out of the .rar (it can still be extracted again)
        public string DeleteNote;
        public long FreedBytes;
        public string Problem;           // fatal, single message
        public List<string> ItemErrors = new List<string>();
        public int FilesExtracted;
        public string PunchProblem;
        public string Log;
        public TimeSpan Elapsed;
    }

    // ------------------------------------------------------------------------------------------
    // The engine: preflight + extraction + live space freeing
    // ------------------------------------------------------------------------------------------
    sealed class Engine
    {
        // Free only data this far behind the read position...
        public const long Margin = 256 * Util.MiB;
        // ...and never the last stretch of the file.
        public const long TailGuard = 256 * Util.MiB;
        public const long Chunk = 64 * Util.MiB;
        public const long Align = 64 * 1024;
        public const long MaxGap = 128 * Util.MiB; // a read starting further ahead than this is a seek, not progress

        // When the drive fills up mid-run, carry on once this much is free again.
        public const long ResumeFree = 512 * Util.MiB;

        const string Untouched = "Nothing was changed. Extract this one with 7-Zip or WinRAR normally.";

        readonly string archive, dest, sevenZipDll;
        public readonly string Arc; // ".rar" or ".zip", for messages
        readonly bool deleteWhenDone;
        // Only give space back when the .rar and the extract folder share a drive. Otherwise it wouldn't help the
        // extraction fit, and the .rar would be used up for nothing.
        readonly bool freeSpace;
        // Read and check every file before touching anything.
        readonly bool testFirst;
        // Files the pre-flight check counted; the .rar is only deleted if exactly this many were extracted.
        readonly int expectedFiles;

        // Packed bytes of items just skipped (couldn't be written): 7-Zip jumps over their data, and that jump is
        // allowed to count as progress so freeing space doesn't stall for the rest of the run. Worker thread only.
        public long SkipAllowance;

        // live state read by the UI
        public long ArchiveSize;
        public volatile string CurrentFile = "";
        public long trustedPos, punchedTo;
        public volatile string PunchProblemText;
        public volatile string Violation;
        public volatile bool CancelRequested;
        public volatile bool WaitingForSpace;
        public long testPos;
        volatile RunPhase phase;
        DateTime startedUtc;

        readonly List<string> logLines = new List<string>();
        readonly List<string> itemErrors = new List<string>();
        readonly object logLock = new object();
        public int FilesDone, FilesTested;
        public long BytesWritten; // worker thread only

        public Engine(Preflight p, bool deleteWhenDone, bool freeSpace, bool testFirst)
        {
            archive = p.Archive;
            Arc = Util.ArcName(archive);
            dest = p.Dest;
            sevenZipDll = p.SevenZipDll;
            ArchiveSize = p.ArchiveBytes;
            expectedFiles = p.FileCount;
            this.deleteWhenDone = deleteWhenDone;
            this.freeSpace = freeSpace;
            // When the .rar is left alone, a failed extraction loses nothing, so there's no need to test first.
            this.testFirst = testFirst && freeSpace;
        }

        public bool FreesSpace { get { return freeSpace; } }
        public bool TestsFirst { get { return testFirst; } }
        public string DestDrive { get { return Path.GetPathRoot(dest); } }
        public long TrustedPos { get { return Interlocked.Read(ref trustedPos); } }
        public long PunchedTo { get { return Interlocked.Read(ref punchedTo); } }
        public long TestPos { get { return Interlocked.Read(ref testPos); } }
        public RunPhase Phase { get { return phase; } }
        public bool Extracting { get { return phase == RunPhase.Extracting; } }
        public TimeSpan Elapsed { get { return startedUtc == default(DateTime) ? TimeSpan.Zero : DateTime.UtcNow - startedUtc; } }
        public long AllocatedNow { get { return Util.AllocatedSize(archive); } }

        public void Cancel() { CancelRequested = true; }

        public void AddItemError(string text) { lock (logLock) { if (itemErrors.Count < 1000) itemErrors.Add(text); } }
        public void AddLog(string text) { lock (logLock) { if (logLines.Count < 400) logLines.Add(text); } }
        public void BeginExtraction() { phase = RunPhase.Extracting; }

        // Called on the worker when the extract drive is full. Something else used the space (a download, Windows
        // Update, restore points...), and failing now could leave a half-used .rar. So wait until there's room
        // again and let the write carry on. Returns false if the user cancels instead.
        public bool WaitForSpace()
        {
            WaitingForSpace = true;
            AddLog("The drive filled up at " + DateTime.Now.ToString("T", CultureInfo.CurrentCulture) + "; waited for free space.");
            try
            {
                while (!CancelRequested)
                {
                    Thread.Sleep(1000);
                    if (Util.FreeSpace(dest) >= ResumeFree) return true;
                }
                return false;
            }
            finally { WaitingForSpace = false; }
        }

#if CLI
        public static bool TestOnly;        // test harness: open the archive read-only and stop after the test pass
        static bool TestOnlyRun { get { return TestOnly; } }
#else
        static bool TestOnlyRun { get { return false; } }
#endif
#if CLI
        public static long TestFullAt = -1; // test harness: pretend the drive is full for 3 s once this much is written
        DateTime testFullUntil;

        public bool TestDiskFull()
        {
            if (TestFullAt < 0 || BytesWritten < TestFullAt) return false;
            if (testFullUntil == default(DateTime)) testFullUntil = DateTime.UtcNow.AddSeconds(3);
            if (DateTime.UtcNow < testFullUntil) return true;
            TestFullAt = -1;
            return false;
        }
#endif

        // ---------------------------------------------------------------- pre-flight
        public static Preflight Check(string archivePath, string destPath, string dllPath)
        {
            Preflight p = new Preflight();
            try { CheckCore(p, archivePath, destPath, dllPath); }
            catch (Exception ex) { p.Error = "Couldn't check things: " + ex.Message; }
            return p;
        }

        static void CheckCore(Preflight p, string archivePath, string destPath, string dllPath)
        {
            archivePath = (archivePath ?? "").Trim().Trim('"');
            destPath = (destPath ?? "").Trim().Trim('"');
            dllPath = (dllPath ?? "").Trim().Trim('"');

            if (archivePath.Length == 0) { p.Error = "Pick the .rar or .zip file first."; return; }
            string archive = Path.GetFullPath(archivePath);
            if (!File.Exists(archive)) { p.Error = "That file doesn't exist:\n" + archive; return; }
            string arc = Util.ArcName(archive);
            if (arc == "archive") { p.Error = "That doesn't look like a .rar or .zip file."; return; }
            if (Regex.IsMatch(Path.GetFileName(archive), @"\.part0*\d+\.rar$", RegexOptions.IgnoreCase) ||
                File.Exists(Path.ChangeExtension(archive, ".r00")) || File.Exists(Path.ChangeExtension(archive, ".z01")))
            {
                p.Error = "This looks like one piece of a split archive (.part1.rar / .r00 / .z01). This app only handles a single archive file.";
                return;
            }

            if (dllPath.Length == 0) { p.Error = "Pick 7-Zip's 7z.dll (install 7-Zip first if you don't have it)."; return; }
            string dll = Path.GetFullPath(dllPath);
            if (!File.Exists(dll)) { p.Error = "7z.dll not found:\n" + dll; return; }
            if (!string.Equals(Path.GetFileName(dll), "7z.dll", StringComparison.OrdinalIgnoreCase))
            { p.Error = "Please pick the file named 7z.dll (in the 7-Zip folder)."; return; }

            if (destPath.Length == 0) { p.Error = "Pick the folder to extract into."; return; }
            string dest = Path.GetFullPath(destPath);
            string root = Path.GetPathRoot(dest);
            if (!string.IsNullOrEmpty(root) && string.Equals(dest.TrimEnd('\\', '/'), root.TrimEnd('\\', '/'), StringComparison.OrdinalIgnoreCase))
            { p.Error = "Pick a folder to extract into, not a whole drive."; return; }
            dest = dest.TrimEnd('\\', '/');
            if (File.Exists(dest)) { p.Error = "A file with that name already exists:\n" + dest; return; }
            if (Directory.Exists(dest))
            {
                bool any = false;
                foreach (string e in Directory.EnumerateFileSystemEntries(dest)) { any = true; break; }
                if (any)
                {
                    p.Error = "The extract folder isn't empty:\n" + dest + "\n\nPick an empty or new folder so nothing gets overwritten.";
                    return;
                }
            }
            string existing = Util.NearestExistingDirectory(dest);
            if (string.IsNullOrEmpty(existing)) { p.Error = "That location doesn't exist:\n" + dest; return; }

            string archiveRoot = Util.VolumeRoot(archive);
            string destRoot = Util.VolumeRoot(existing);
            if (archiveRoot == null || destRoot == null) { p.Error = "Couldn't read the drive information."; return; }
            if (!Util.SupportsSparse(archiveRoot))
            {
                p.Error = "The drive holding the " + arc + " (" + archiveRoot + ") doesn't support freeing space on the fly (it needs NTFS).\n" +
                          "Extract this one with 7-Zip or WinRAR normally, or move the " + arc + " to an NTFS drive.";
                return;
            }

            string err;
            SevenZipLib lib = SevenZipLib.Load(dll, out err);
            if (lib == null) { p.Error = err; return; }

            long archiveBytes = new FileInfo(archive).Length;

            // Holes in the archive mean data is missing: a torrent client that hasn't finished (they fill files in out
            // of order and leave the rest empty), or an earlier run of this app that was stopped.
            FileAttributes attrs = File.GetAttributes(archive);
            if ((attrs & FileAttributes.SparseFile) != 0 && (attrs & FileAttributes.Compressed) == 0)
            {
                long alloc = Util.AllocatedSize(archive);
                if (alloc >= 0 && alloc < archiveBytes)
                {
                    p.Error = "Parts of this " + arc + " are missing (" + Util.Size(archiveBytes - alloc) + " of it is empty space on disk).\n\n" +
                              "It's probably still downloading (torrent clients fill files in out of order), or an earlier run of this " +
                              "app was stopped part-way and already used it up. Nothing was changed.";
                    return;
                }
            }

            List<long> sizes = new List<long>(), packs = new List<long>();
            bool solid = false, encrypted = false, split = false;
            bool outOfOrder = false, gappy = false;
            long lastOffset = -1, lastEnd = 0;
            int files = 0;
            long totalUnpacked = 0, totalPacked = 0;

            using (FileStream fs = new FileStream(archive, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1))
            {
                byte[] head = new byte[8];
                int got = fs.Read(head, 0, 8);
                fs.Position = 0;
                if (got < 4) { p.Error = "That file is too small to be an archive."; return; }
                IInArchive arch = lib.CreateHandler(head, out err);
                if (arch == null) { p.Error = err; return; }
                try
                {
                    ReadOnlyStream rs = new ReadOnlyStream(fs);
                    IntPtr maxCheck = Marshal.AllocCoTaskMem(8);
                    Marshal.WriteInt64(maxCheck, 1L << 20);
                    int hr;
                    try { hr = arch.Open(rs, maxCheck, IntPtr.Zero); }
                    finally { Marshal.FreeCoTaskMem(maxCheck); }
                    if (hr != 0)
                    {
                        p.Error = "7-Zip couldn't read this archive (error 0x" + hr.ToString("X8", CultureInfo.InvariantCulture) +
                                  ").\nIt may be damaged, password-protected, or not finished downloading.";
                        return;
                    }
                    string damage = SevenZipLib.ArchiveDamage(arch);
                    if (damage != null)
                    {
                        p.Error = "7-Zip found problems in this archive: " + damage + ".\n" +
                                  "It may be damaged or not finished downloading. Nothing was changed.";
                        return;
                    }
                    uint n;
                    arch.GetNumberOfItems(out n);
                    HashSet<string> fileNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    HashSet<string> folders = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    for (uint i = 0; i < n; i++)
                    {
                        // Every name must be usable before anything is touched: a file that can't be written
                        // would be lost for good once the .rar is used up.
                        string raw = SevenZipLib.PropPath(arch, i), rel, why;
                        bool renamed;
                        if (!Util.TrySafeRelativePath(raw, out rel, out renamed, out why))
                        {
                            p.Error = "A name inside the archive can't be used on Windows (" + why + "):\n" + (raw ?? "item " + i) + "\n\n" + Untouched;
                            return;
                        }
                        if (dest.Length + 1 + rel.Length > 32000)
                        {
                            p.Error = "A path inside the archive is too long for Windows:\n" + rel + "\n\n" + Untouched;
                            return;
                        }
                        // Where each item sits in the file (ZIP reports it). Space is freed behind the read position, so
                        // the items must come in the order they'll be extracted, with no big unused stretches between.
                        long off = SevenZipLib.PropOffset(arch, i);
                        if (off >= 0)
                        {
                            if (off <= lastOffset) outOfOrder = true;
                            else if (off - lastEnd > Engine.MaxGap / 2) gappy = true;
                            lastOffset = off;
                            lastEnd = off + Math.Max(0, SevenZipLib.PropPackSize(arch, i));
                        }
                        if (renamed && p.RenamedCount++ == 0) p.RenamedExample = "\"" + raw + "\"  ->  \"" + rel + "\"";
                        for (int k = rel.IndexOf('\\'); k >= 0; k = rel.IndexOf('\\', k + 1)) folders.Add(rel.Substring(0, k));
                        if (SevenZipLib.PropIsDir(arch, i)) { folders.Add(rel); continue; }
                        if (!fileNames.Add(rel))
                        {
                            p.Error = "Two files inside the archive would end up with the same name:\n" + rel + "\n\n" +
                                      "(Windows doesn't tell upper and lower case apart, and characters it doesn't allow become \"_\".)\n\n" + Untouched;
                            return;
                        }
                        long size = SevenZipLib.PropSize(arch, i);
                        long pack = SevenZipLib.PropPackSize(arch, i);
                        if (SevenZipLib.PropEncrypted(arch, i)) encrypted = true;
                        if (SevenZipLib.PropSplit(arch, i)) split = true;
                        if (SevenZipLib.PropSolid(arch, i)) solid = true;
                        if (size < 0) { p.Error = "Couldn't read the size of one of the files inside the archive."; return; }
                        sizes.Add(size);
                        packs.Add(pack < 0 ? 0 : pack);
                        totalUnpacked += size;
                        totalPacked += pack < 0 ? 0 : pack;
                        files++;
                    }
                    foreach (string f in fileNames)
                        if (folders.Contains(f))
                        {
                            p.Error = "\"" + f + "\" is both a file and a folder inside the archive.\n\n" + Untouched;
                            return;
                        }
                    arch.Close();
                }
                finally { Marshal.ReleaseComObject(arch); }
            }

            if (encrypted) { p.Error = "This archive is password-protected. Password-protected archives aren't supported here."; return; }
            if (split) { p.Error = "This archive continues in other volumes (split archive). This app only handles a single archive file."; return; }
            if (files == 0) { p.Error = "Couldn't find any files inside this archive."; return; }
            if (totalPacked > archiveBytes)
            {
                p.Error = "This archive looks incomplete: the files inside need " + Util.Size(totalPacked) + " of packed data but the " + arc + " is only " +
                          Util.Size(archiveBytes) + ".\nIt probably hasn't finished downloading.";
                return;
            }

            // Worst moment for disk usage: extracted-so-far minus what has been given back so far.
            long cumU = 0, cumP = 0, peak = 0;
            long maxPunch = Math.Max(0, archiveBytes - Engine.TailGuard);
            for (int i = 0; i < sizes.Count; i++)
            {
                cumU += sizes[i];
                long punchedEstimate;
                if (solid)
                    punchedEstimate = 0; // can't tell where inside a solid block we are: assume nothing freed (cautious)
                else
                {
                    cumP += packs[i];
                    punchedEstimate = Math.Min(Math.Max(0, cumP - Engine.Margin), maxPunch);
                }
                long extra = cumU - punchedEstimate + Engine.Chunk; // space is handed back in chunks, so allow one chunk of lag
                if (extra > peak) peak = extra;
            }

            bool sameVolume = string.Equals(archiveRoot, destRoot, StringComparison.OrdinalIgnoreCase);
            if (sameVolume && (outOfOrder || gappy))
            {
                p.Error = (outOfOrder ? "The files inside this " + arc + " aren't stored in the order they get extracted"
                                      : "This " + arc + " has large unused stretches between the files inside it") +
                          ", so space can't safely be given back as it goes.\n\n" + Untouched +
                          "\n(Or pick an extract folder on a different drive: then the " + arc + " is left untouched and it works.)";
                return;
            }
            long slack = Math.Max(512 * Util.MiB, totalUnpacked / 50);
            long needed = (sameVolume ? peak : totalUnpacked) + slack;
            long free = Util.FreeSpace(existing);
            if (free < 0) { p.Error = "Couldn't read the free space of " + destRoot; return; }

            p.Archive = archive; p.Dest = dest; p.SevenZipDll = dll;
            p.ArchiveBytes = archiveBytes; p.UnpackedBytes = totalUnpacked; p.FileCount = files;
            p.PeakExtra = peak; p.NeededFree = needed; p.FreeBytes = free;
            p.SameVolume = sameVolume; p.Solid = solid; p.DestRoot = destRoot;

            if (free < needed)
            {
                p.Error = "Not enough free space on " + destRoot + " for this extraction.\n\n" +
                          "Needed (with a safety cushion): " + Util.Size(needed) + "\n" +
                          "Free right now: " + Util.Size(free) + "\n\n" +
                          "Free up some space, or pick an extract folder on another drive.";
            }
        }

        // ---------------------------------------------------------------- run
        public RunResult Run()
        {
            RunResult res = new RunResult();
            res.ArchiveIntact = true;
            SafeFileHandle fh = null;
            FileStream fs = null;
            IInArchive arch = null;
            startedUtc = DateTime.UtcNow;
            try
            {
                ArchiveSize = new FileInfo(archive).Length;
                string err;
                SevenZipLib lib = SevenZipLib.Load(sevenZipDll, out err);
                if (lib == null) { res.StartFailed = true; res.Problem = err; return res; }

                // The one and only handle on the .rar: used to read it (for 7-Zip) and to free space in it. Others may
                // only read it, so a program that's still writing it (e.g. a torrent client) makes this fail up front.
                uint access = freeSpace && !TestOnlyRun ? NativeMethods.GENERIC_READ | NativeMethods.GENERIC_WRITE : NativeMethods.GENERIC_READ;
                fh = NativeMethods.CreateFileW(archive, access, NativeMethods.FILE_SHARE_READ, IntPtr.Zero,
                    NativeMethods.OPEN_EXISTING, NativeMethods.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (fh.IsInvalid)
                {
                    res.StartFailed = true;
                    res.Problem = "Couldn't open the " + Arc + (freeSpace ? " for writing" : "") + " (" + new Win32Exception(Marshal.GetLastWin32Error()).Message +
                                  "). Is it read-only, or open in another program (for example a torrent client still downloading or seeding it)? Nothing was changed.";
                    return res;
                }
                fs = new FileStream(fh, FileAccess.Read, 1, false);

                byte[] head = new byte[8];
                int got = fs.Read(head, 0, 8);
                fs.Position = 0;
                arch = lib.CreateHandler(head, out err);
                if (arch == null) { res.StartFailed = true; res.Problem = err; return res; }

                ArchiveStream ins = new ArchiveStream(this, fs, fh);
                IntPtr maxCheck = Marshal.AllocCoTaskMem(8);
                Marshal.WriteInt64(maxCheck, 1L << 20);
                int hr;
                try { hr = arch.Open(ins, maxCheck, IntPtr.Zero); }
                finally { Marshal.FreeCoTaskMem(maxCheck); }
                if (hr != 0)
                {
                    res.StartFailed = true;
                    res.Problem = "7-Zip couldn't read this archive (error 0x" + hr.ToString("X8", CultureInfo.InvariantCulture) + "). Nothing was extracted.";
                    return res;
                }

                if ((!testFirst || TestArchive(arch, res)) && !TestOnlyRun) ExtractAll(arch, fh, res);
                arch.Close();
            }
            catch (Exception ex)
            {
                res.Problem = ex.Message;
                res.StartFailed = phase == RunPhase.Opening; // nothing has been touched yet
            }
            finally
            {
                phase = RunPhase.Finishing;
                if (arch != null) { try { Marshal.ReleaseComObject(arch); } catch (Exception) { } }
                if (fs != null) { try { fs.Dispose(); } catch (Exception) { } }
                if (fh != null) { try { fh.Dispose(); } catch (Exception) { } }
            }
            return Finish(res);
        }

        // The real extraction. From here on the .rar gets used up.
        void ExtractAll(IInArchive arch, SafeFileHandle fh, RunResult res)
        {
            uint ret;
            if (freeSpace && !NativeMethods.DeviceIoControlNoBuffer(fh, NativeMethods.FSCTL_SET_SPARSE, IntPtr.Zero, 0, IntPtr.Zero, 0, out ret, IntPtr.Zero))
            {
                res.StartFailed = true;
                res.Problem = "Windows refused to mark the " + Arc + " as sparse (" + new Win32Exception(Marshal.GetLastWin32Error()).Message +
                              "). Nothing was extracted.";
                return;
            }
            Util.EnsureDirectory(dest);
            ExtractCallback cb = new ExtractCallback(this, arch, dest);
            BeginExtraction();
            int hr = arch.Extract(IntPtr.Zero, 0xFFFFFFFF, 0, cb);
            cb.FinishLastItem();
            phase = RunPhase.Finishing;
            cb.ApplyFolderTimes();

            res.FilesExtracted = cb.FilesOk;
            res.Cancelled = CancelRequested;
            if (Violation != null) res.Problem = Violation;
            else if (hr != 0 && !res.Cancelled && itemErrors.Count == 0 && res.Problem == null)
                res.Problem = LastProblem ?? ("7-Zip stopped with error 0x" + hr.ToString("X8", CultureInfo.InvariantCulture) + ".");
            res.Success = hr == 0 && !res.Cancelled && Violation == null && itemErrors.Count == 0 && res.Problem == null;
            if (res.Problem == null && LastProblem != null && !res.Success && !res.Cancelled) res.Problem = LastProblem;
            // Last line of defence before the .rar is deleted: every file the check counted must be there.
            if (res.Success && cb.FilesOk != expectedFiles)
            {
                res.Success = false;
                res.Problem = "Only " + cb.FilesOk + " of the " + expectedFiles + " files in the archive were extracted.";
            }
        }

        // Reads and checks every file (7-Zip's "test") without writing anything or touching the .rar, so a damaged
        // archive is caught while it can still be extracted some other way. True if everything checked out.
        bool TestArchive(IInArchive arch, RunResult res)
        {
            phase = RunPhase.Testing;
            TestCallback cb = new TestCallback(this, arch);
            int hr = arch.Extract(IntPtr.Zero, 0xFFFFFFFF, 1, cb);
            phase = RunPhase.Opening;
            if (CancelRequested) { res.Cancelled = true; return false; }
            if (hr == 0 && cb.Bad == 0 && cb.FilesOk == expectedFiles) return true;
            res.TestFailed = true;
            if (cb.Bad == 0)
                res.Problem = hr != 0
                    ? LastProblem ?? ("7-Zip stopped with error 0x" + hr.ToString("X8", CultureInfo.InvariantCulture) + ".")
                    : "Only " + cb.FilesOk + " of the " + expectedFiles + " files in the archive could be checked.";
            return false;
        }

        // Wraps up a run that got past opening the .rar: what was freed, deleting the leftover, the error lists.
        RunResult Finish(RunResult res)
        {
            phase = RunPhase.Finishing;
            res.Elapsed = DateTime.UtcNow - startedUtc;
            res.ArchiveIntact = PunchedTo == 0;
            long alloc = Util.AllocatedSize(archive);
            if (alloc >= 0 && File.Exists(archive)) res.FreedBytes = Math.Max(0, ArchiveSize - alloc);
            res.PunchProblem = PunchProblemText;

            if (res.Success && deleteWhenDone)
            {
                try
                {
                    File.SetAttributes(archive, FileAttributes.Normal);
                    File.Delete(archive);
                    res.ArchiveDeleted = true;
                }
                catch (Exception ex) { res.DeleteNote = "Couldn't delete the leftover " + Arc + ": " + ex.Message; }
            }

            lock (logLock)
            {
                res.ItemErrors.AddRange(itemErrors);
                res.Log = string.Join("\r\n", logLines.ToArray());
            }
            return res;
        }

        public volatile string LastProblem;

        // Called from the stream/callback when something goes wrong (also logged).
        public void NoteProblem(string text)
        {
            if (LastProblem == null) LastProblem = text;
            AddLog(text);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Plain read-only stream for 7-Zip (used only for the pre-flight listing)
    // ------------------------------------------------------------------------------------------
    [ComVisible(true), ClassInterface(ClassInterfaceType.None)]
    sealed class ReadOnlyStream : IInStream
    {
        readonly FileStream fs;
        byte[] buf = new byte[1 << 20];
        public ReadOnlyStream(FileStream fs) { this.fs = fs; }

        public int Read(IntPtr data, uint size, IntPtr processed)
        {
            try
            {
                int want = (int)Math.Min(size, (uint)buf.Length);
                int n = want == 0 ? 0 : fs.Read(buf, 0, want);
                if (n > 0) Marshal.Copy(buf, 0, data, n);
                if (processed != IntPtr.Zero) Marshal.WriteInt32(processed, n);
                return 0;
            }
            catch (Exception) { return SevenZipLib.E_FAIL; }
        }

        public int Seek(long offset, uint origin, IntPtr newPosition)
        {
            try
            {
                if (origin > 2) return SevenZipLib.E_FAIL;
                long pos = fs.Seek(offset, (SeekOrigin)origin);
                if (newPosition != IntPtr.Zero) Marshal.WriteInt64(newPosition, pos);
                return 0;
            }
            catch (Exception) { return SevenZipLib.E_FAIL; }
        }
    }

    // ------------------------------------------------------------------------------------------
    // The .rar as 7-Zip sees it. Every byte 7-Zip reads goes through here, so we know exactly how
    // far extraction has got and can free everything safely behind it.
    // ------------------------------------------------------------------------------------------
    [ComVisible(true), ClassInterface(ClassInterfaceType.None)]
    sealed class ArchiveStream : IInStream
    {
        readonly Engine owner;
        readonly FileStream fs;
        readonly SafeFileHandle handle;
        byte[] buf = new byte[1 << 20];
        long trusted;          // furthest believable read position (end of the last sequential read)
        long punched;          // everything below this has been given back
        bool punchBroken;

        public ArchiveStream(Engine owner, FileStream fs, SafeFileHandle handle)
        {
            this.owner = owner; this.fs = fs; this.handle = handle;
        }

        public int Read(IntPtr data, uint size, IntPtr processed)
        {
            try
            {
                if (owner.CancelRequested) return SevenZipLib.E_ABORT;
                if (size == 0)
                {
                    if (processed != IntPtr.Zero) Marshal.WriteInt32(processed, 0);
                    return 0;
                }
                long start = fs.Position;
                if (owner.Extracting && start < punched)
                {
                    // Must never happen: would mean handing zeros to the extractor.
                    owner.Violation = "Extraction needed data it had already given back (at " + Util.Size(start) +
                                      "). This kind of archive can't be extracted with space-saving. Extract it with WinRAR/7-Zip normally.";
                    owner.NoteProblem(owner.Violation);
                    return SevenZipLib.E_FAIL;
                }
                int want = (int)Math.Min(size, (uint)buf.Length);
                int n = fs.Read(buf, 0, want);
                if (n > 0) Marshal.Copy(buf, 0, data, n);
                if (processed != IntPtr.Zero) Marshal.WriteInt32(processed, n);
                if (n > 0)
                {
                    if (owner.Extracting) Advance(start, start + n);
                    else if (owner.Phase == RunPhase.Testing && start + n > owner.TestPos)
                        Interlocked.Exchange(ref owner.testPos, start + n); // progress display only
                }
                return 0;
            }
            catch (Exception ex)
            {
                owner.NoteProblem("Reading the " + owner.Arc + " failed: " + ex.Message);
                return SevenZipLib.E_FAIL;
            }
        }

        public int Seek(long offset, uint origin, IntPtr newPosition)
        {
            try
            {
                if (origin > 2) return SevenZipLib.E_FAIL;
                long pos = fs.Seek(offset, (SeekOrigin)origin);
                if (newPosition != IntPtr.Zero) Marshal.WriteInt64(newPosition, pos);
                return 0;
            }
            catch (Exception ex)
            {
                owner.NoteProblem("Seeking in the " + owner.Arc + " failed: " + ex.Message);
                return SevenZipLib.E_FAIL;
            }
        }

        void Advance(long start, long end)
        {
            // A read that starts far beyond what we've followed is a seek (e.g. to the end of the archive),
            // not progress. Never trust it - unless it's 7-Zip jumping over the data of items we just skipped.
            long gap = start - trusted;
            if (gap > Engine.MaxGap)
            {
                if (gap > Engine.MaxGap + owner.SkipAllowance) return;
                owner.SkipAllowance = 0;
            }
            if (end > trusted)
            {
                trusted = end;
                Interlocked.Exchange(ref owner.trustedPos, trusted);
            }
            if (punchBroken || !owner.FreesSpace) return;

            long limit = Math.Min(trusted - Engine.Margin, owner.ArchiveSize - Engine.TailGuard);
            long target = limit & ~(Engine.Align - 1);
            if (target - punched < Engine.Chunk) return;

            NativeMethods.FILE_ZERO_DATA_INFORMATION z = new NativeMethods.FILE_ZERO_DATA_INFORMATION();
            z.FileOffset = punched;
            z.BeyondFinalZero = target;
            uint ret;
            if (NativeMethods.DeviceIoControlZeroData(handle, NativeMethods.FSCTL_SET_ZERO_DATA, ref z,
                    (uint)Marshal.SizeOf(typeof(NativeMethods.FILE_ZERO_DATA_INFORMATION)), IntPtr.Zero, 0, out ret, IntPtr.Zero))
            {
                punched = target;
                Interlocked.Exchange(ref owner.punchedTo, punched);
            }
            else
            {
                punchBroken = true;
                owner.PunchProblemText = "Windows stopped giving space back (" + new Win32Exception(Marshal.GetLastWin32Error()).Message +
                                         "). The extraction itself carried on normally.";
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Writes one extracted file. Writes go straight to Windows, so we always know exactly how much
    // landed on disk: if the drive fills up, it waits for space and carries on from that byte
    // instead of failing (by then the .rar may already be partly used up).
    // ------------------------------------------------------------------------------------------
    [ComVisible(true), ClassInterface(ClassInterfaceType.None)]
    sealed class FileOutStream : ISequentialOutStream
    {
        readonly Engine owner;
        readonly SafeFileHandle handle;
        readonly string name;
        public bool Failed;

        public FileOutStream(Engine owner, SafeFileHandle handle, string name)
        {
            this.owner = owner; this.handle = handle; this.name = name;
        }

        public int Write(IntPtr data, uint size, IntPtr processed)
        {
            try
            {
                uint done = 0;
                while (done < size)
                {
                    if (owner.CancelRequested) return SevenZipLib.E_ABORT;
                    uint wrote;
                    int err = WriteSome(new IntPtr(data.ToInt64() + done), size - done, out wrote);
                    if (err == NativeMethods.ERROR_DISK_FULL || err == NativeMethods.ERROR_HANDLE_DISK_FULL)
                    {
                        if (!owner.WaitForSpace()) return SevenZipLib.E_ABORT; // cancelled while waiting
                        continue;
                    }
                    if (err != 0) throw new IOException(new Win32Exception(err).Message);
                    if (wrote == 0) throw new IOException("Windows wrote nothing.");
                    done += wrote;
                    owner.BytesWritten += wrote;
                }
                if (processed != IntPtr.Zero) Marshal.WriteInt32(processed, (int)size);
                return 0;
            }
            catch (Exception ex)
            {
                Failed = true;
                owner.NoteProblem("Couldn't write \"" + name + "\": " + ex.Message);
                return SevenZipLib.E_FAIL;
            }
        }

        int WriteSome(IntPtr data, uint count, out uint wrote)
        {
#if CLI
            if (owner.TestDiskFull()) { wrote = 0; return NativeMethods.ERROR_DISK_FULL; }
#endif
            return NativeMethods.WriteFile(handle, data, count, out wrote, IntPtr.Zero) ? 0 : Marshal.GetLastWin32Error();
        }

        public void Finish(long fileTime)
        {
            try { if (fileTime > 0) NativeMethods.SetFileTime(handle, IntPtr.Zero, IntPtr.Zero, ref fileTime); }
            catch (Exception) { }
            try { handle.Dispose(); } catch (Exception) { }
        }
    }

    // ------------------------------------------------------------------------------------------
    // 7-Zip asks us where to put each item and tells us how it went
    // ------------------------------------------------------------------------------------------
    [ComVisible(true), ClassInterface(ClassInterfaceType.None)]
    sealed class ExtractCallback : IArchiveExtractCallback
    {
        readonly Engine owner;
        readonly IInArchive arch;
        readonly string root;
        FileOutStream current;
        string currentName;
        long currentTime;
        bool currentIsFile;
        public int FilesOk;
        readonly List<KeyValuePair<string, long>> folderTimes = new List<KeyValuePair<string, long>>();

        public ExtractCallback(Engine owner, IInArchive arch, string root)
        {
            this.owner = owner; this.arch = arch; this.root = root;
        }

        public int SetTotal(ulong total) { return owner.CancelRequested ? SevenZipLib.E_ABORT : 0; }
        public int SetCompleted(IntPtr completeValue) { return owner.CancelRequested ? SevenZipLib.E_ABORT : 0; }

        public int GetStream(uint index, out ISequentialOutStream outStream, int askExtractMode)
        {
            outStream = null;
            try
            {
                FinishLastItem(); // in case 7-Zip didn't call SetOperationResult for the previous one
                currentIsFile = false;
                if (owner.CancelRequested) return SevenZipLib.E_ABORT;
                if (askExtractMode != 0) return 0; // test/skip: nothing to write

                string raw = SevenZipLib.PropPath(arch, index);
                bool isDir = SevenZipLib.PropIsDir(arch, index);
                string rel, why;
                bool renamed;
                currentName = raw ?? ("item " + index);
                if (!Util.TrySafeRelativePath(raw, out rel, out renamed, out why))
                {
                    owner.AddItemError("Skipped \"" + currentName + "\": " + why);
                    Skip(index);
                    return 0; // null stream: 7-Zip skips the data
                }
                currentName = rel;
                string full = root + "\\" + rel;

                if (isDir)
                {
                    Util.EnsureDirectory(full);
                    folderTimes.Add(new KeyValuePair<string, long>(full, SevenZipLib.PropMTime(arch, index)));
                    return 0;
                }

                string parent = Util.ParentOf(full);
                if (parent != null) Util.EnsureDirectory(parent);

#if CLI
                if (TestFailCreate != null && string.Equals(rel, TestFailCreate, StringComparison.OrdinalIgnoreCase))
                {
                    owner.AddItemError("Couldn't create \"" + currentName + "\": simulated failure (test)");
                    Skip(index);
                    return 0;
                }
#endif
                SafeFileHandle h = NativeMethods.CreateFileW(Util.LongPath(full), NativeMethods.GENERIC_WRITE,
                    NativeMethods.FILE_SHARE_READ, IntPtr.Zero, NativeMethods.CREATE_NEW, NativeMethods.FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                if (h.IsInvalid)
                {
                    int e = Marshal.GetLastWin32Error();
                    owner.AddItemError("Couldn't create \"" + currentName + "\": " + (e == 80 || e == 183 ? "a file with that name already exists" : new Win32Exception(e).Message));
                    Skip(index);
                    return 0; // skip its data
                }
                Util.TryReserve(h, SevenZipLib.PropSize(arch, index), root);
                current = new FileOutStream(owner, h, currentName);
                currentTime = SevenZipLib.PropMTime(arch, index);
                currentIsFile = true;
                owner.CurrentFile = currentName;
                outStream = current;
                return 0;
            }
            catch (Exception ex)
            {
                owner.AddItemError("Couldn't extract \"" + currentName + "\": " + ex.Message);
                owner.NoteProblem(ex.Message);
                return SevenZipLib.E_FAIL;
            }
        }

#if CLI
        public static string TestFailCreate; // test harness: pretend this file can't be created
#endif

        // The item won't be written; 7-Zip will jump over its data, and that jump has to count as progress.
        void Skip(uint index)
        {
            owner.SkipAllowance += Math.Max(0, SevenZipLib.PropPackSize(arch, index));
        }

        public int PrepareOperation(int askExtractMode) { return owner.CancelRequested ? SevenZipLib.E_ABORT : 0; }

        public int SetOperationResult(int operationResult)
        {
            try
            {
                bool wasFile = currentIsFile;
                bool writeFailed = current != null && current.Failed;
                FinishLastItem();
                if (wasFile)
                {
                    owner.SkipAllowance = 0; // reading resumed after any skip; don't let it linger
                    if (operationResult == 0 && !writeFailed) { FilesOk++; owner.FilesDone = FilesOk; }
                    else if (operationResult != 0) owner.AddItemError("\"" + currentName + "\": " + SevenZipLib.DescribeResult(operationResult));
                }
            }
            catch (Exception ex) { owner.NoteProblem(ex.Message); }
            return owner.CancelRequested ? SevenZipLib.E_ABORT : 0;
        }

        public void FinishLastItem()
        {
            if (current != null)
            {
                current.Finish(currentTime);
                current = null;
            }
            currentIsFile = false;
        }

        // Gives folders their dates from the archive. Runs last, because writing files into a folder changes its date.
        public void ApplyFolderTimes()
        {
            folderTimes.Sort(delegate(KeyValuePair<string, long> a, KeyValuePair<string, long> b) { return b.Key.Length.CompareTo(a.Key.Length); });
            foreach (KeyValuePair<string, long> f in folderTimes) Util.SetFolderTime(f.Key, f.Value);
        }
    }

    // ------------------------------------------------------------------------------------------
    // The test pass: 7-Zip decodes and checks every file; nothing is written
    // ------------------------------------------------------------------------------------------
    [ComVisible(true), ClassInterface(ClassInterfaceType.None)]
    sealed class TestCallback : IArchiveExtractCallback
    {
        readonly Engine owner;
        readonly IInArchive arch;
        string currentName;
        bool currentIsFile;
        public int FilesOk, Bad;

        public TestCallback(Engine owner, IInArchive arch)
        {
            this.owner = owner; this.arch = arch;
        }

        public int SetTotal(ulong total) { return owner.CancelRequested ? SevenZipLib.E_ABORT : 0; }
        public int SetCompleted(IntPtr completeValue) { return owner.CancelRequested ? SevenZipLib.E_ABORT : 0; }

        public int GetStream(uint index, out ISequentialOutStream outStream, int askExtractMode)
        {
            outStream = null; // test mode: 7-Zip checks the data and throws it away
            currentName = SevenZipLib.PropPath(arch, index) ?? ("item " + index);
            currentIsFile = !SevenZipLib.PropIsDir(arch, index);
            if (currentIsFile) owner.CurrentFile = currentName;
            return owner.CancelRequested ? SevenZipLib.E_ABORT : 0;
        }

        public int PrepareOperation(int askExtractMode) { return owner.CancelRequested ? SevenZipLib.E_ABORT : 0; }

        public int SetOperationResult(int operationResult)
        {
            if (currentIsFile)
            {
                if (operationResult == 0) owner.FilesTested = ++FilesOk;
                else { Bad++; owner.AddItemError("\"" + currentName + "\": " + SevenZipLib.DescribeResult(operationResult)); }
            }
            currentIsFile = false;
            return owner.CancelRequested ? SevenZipLib.E_ABORT : 0;
        }
    }

#if !CLI
    // ------------------------------------------------------------------------------------------
    // The window
    // ------------------------------------------------------------------------------------------
    sealed class MainForm : Form
    {
        static readonly Color WarnColor = Color.FromArgb(170, 70, 0);

        TextBox txtRar, txtDest, txtDll, txtLog;
        CheckBox chkTest, chkDelete;
        Button btnRar, btnDest, btnDll, btnStart, btnCancel;
        ProgressBar bar;
        Label lblStatus, lblStats;
        TableLayoutPanel layoutRoot;
        readonly List<Label> wrapLabels = new List<Label>();
        System.Windows.Forms.Timer timer;
        Engine engine;
        bool running;
        bool destEdited;

        public MainForm()
        {
            Text = "Archive Space Saver";
            AutoScaleDimensions = new SizeF(96F, 96F);
            AutoScaleMode = AutoScaleMode.Dpi;
            ClientSize = new Size(780, 620);
            MinimumSize = new Size(700, 580);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Segoe UI", 9F);

            TableLayoutPanel root = layoutRoot = new TableLayoutPanel();
            root.Dock = DockStyle.Fill;
            root.Padding = new Padding(16);
            root.ColumnCount = 1;
            root.RowCount = 10;
            for (int i = 0; i < 9; i++) root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
            Controls.Add(root);

            Label title = new Label();
            title.Text = "Archive Space Saver";
            title.Font = new Font("Segoe UI Semibold", 16F);
            title.AutoSize = true;
            root.Controls.Add(title, 0, 0);

            Label sub = new Label();
            sub.Text = "Extracts a single .rar or .zip and gives the archive's disk space back as it goes, so a 50 GB download needs about 50 GB free instead of 100 GB.";
            sub.AutoSize = true;
            sub.Margin = new Padding(3, 0, 3, 10);
            root.Controls.Add(sub, 0, 1);

            TableLayoutPanel grid = new TableLayoutPanel();
            grid.ColumnCount = 3;
            grid.AutoSize = true;
            grid.Dock = DockStyle.Top;
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
            grid.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            txtRar = AddRow(grid, 0, "Archive (.rar / .zip):", out btnRar);
            txtDest = AddRow(grid, 1, "Extract into:", out btnDest);
            txtDll = AddRow(grid, 2, "7-Zip's 7z.dll:", out btnDll);
            root.Controls.Add(grid, 0, 2);

            chkTest = new CheckBox();
            chkTest.Text = "Test the whole archive before touching it (safer, takes about twice as long)";
            chkTest.Checked = true;
            chkTest.AutoSize = true;
            chkTest.Margin = new Padding(3, 8, 3, 3);
            root.Controls.Add(chkTest, 0, 3);

            chkDelete = new CheckBox();
            chkDelete.Text = "When it finishes without errors, delete the leftover archive (it's just an empty shell by then)";
            chkDelete.Checked = true;
            chkDelete.AutoSize = true;
            chkDelete.Margin = new Padding(3, 3, 3, 3);
            root.Controls.Add(chkDelete, 0, 4);

            Label warn = new Label();
            warn.Text = "Heads up: the archive gets used up while it extracts. If you stop half-way, it can't be finished and you'd have to download it again.";
            warn.ForeColor = WarnColor;
            warn.AutoSize = true;
            warn.Margin = new Padding(3, 4, 3, 8);
            root.Controls.Add(warn, 0, 5);

            FlowLayoutPanel buttons = new FlowLayoutPanel();
            buttons.AutoSize = true;
            buttons.Dock = DockStyle.Top;
            btnStart = new Button();
            btnStart.Text = "Start extracting";
            btnStart.AutoSize = true;
            btnStart.Padding = new Padding(10, 3, 10, 3);
            btnCancel = new Button();
            btnCancel.Text = "Cancel";
            btnCancel.AutoSize = true;
            btnCancel.Padding = new Padding(10, 3, 10, 3);
            btnCancel.Enabled = false;
            buttons.Controls.Add(btnStart);
            buttons.Controls.Add(btnCancel);
            root.Controls.Add(buttons, 0, 6);

            TableLayoutPanel prog = new TableLayoutPanel();
            prog.ColumnCount = 1;
            prog.AutoSize = true;
            prog.Dock = DockStyle.Top;
            bar = new ProgressBar();
            bar.Dock = DockStyle.Top;
            bar.Minimum = 0;
            bar.Maximum = 1000;
            bar.Height = 22;
            lblStatus = new Label();
            lblStatus.AutoSize = true;
            lblStatus.Text = "Ready.";
            lblStats = new Label();
            lblStats.AutoSize = true;
            prog.Controls.Add(bar, 0, 0);
            prog.Controls.Add(lblStatus, 0, 1);
            prog.Controls.Add(lblStats, 0, 2);
            prog.Margin = new Padding(3, 10, 3, 6);
            root.Controls.Add(prog, 0, 7);

            Label logLabel = new Label();
            logLabel.Text = "Messages:";
            logLabel.AutoSize = true;
            root.Controls.Add(logLabel, 0, 8);
            txtLog = new TextBox();
            txtLog.Multiline = true;
            txtLog.ReadOnly = true;
            txtLog.ScrollBars = ScrollBars.Vertical;
            txtLog.Dock = DockStyle.Fill;
            txtLog.Font = new Font("Consolas", 9F);
            root.Controls.Add(txtLog, 0, 9);

            wrapLabels.AddRange(new Label[] { sub, warn, lblStatus, lblStats });
            root.SizeChanged += delegate { FitLabels(); };
            FitLabels();

            txtDll.Text = Util.FindSevenZipDll();
            if (txtDll.Text.Length == 0)
                lblStatus.Text = "The 64-bit 7-Zip wasn't found automatically - install 7-Zip (free) or click Browse next to \"7z.dll\".";

            btnRar.Click += delegate { BrowseRar(); };
            btnDest.Click += delegate { BrowseDest(); };
            btnDll.Click += delegate { BrowseDll(); };
            btnStart.Click += delegate { StartClicked(); };
            btnCancel.Click += delegate { CancelClicked(); };
            txtDest.TextChanged += delegate { if (txtDest.Focused) destEdited = true; };

            timer = new System.Windows.Forms.Timer();
            timer.Interval = 300;
            timer.Tick += delegate { UpdateLive(); };

            FormClosing += OnClosing;
        }

        // Wrapping text follows the window's width (instead of a fixed 740 pixels), so nothing gets cut off.
        void FitLabels()
        {
            int w = Math.Max(200, layoutRoot.ClientSize.Width - layoutRoot.Padding.Horizontal - 12);
            foreach (Label l in wrapLabels)
                if (l.MaximumSize.Width != w) l.MaximumSize = new Size(w, 0);
        }

        static TextBox AddRow(TableLayoutPanel grid, int row, string label, out Button browse)
        {
            Label l = new Label();
            l.Text = label;
            l.AutoSize = true;
            l.Anchor = AnchorStyles.Left;
            l.Margin = new Padding(3, 6, 8, 6);
            TextBox t = new TextBox();
            t.Dock = DockStyle.Fill;
            t.Margin = new Padding(3, 5, 3, 5);
            Button b = new Button();
            b.Text = "Browse...";
            b.AutoSize = true;
            b.Margin = new Padding(3, 3, 3, 3);
            grid.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            grid.Controls.Add(l, 0, row);
            grid.Controls.Add(t, 1, row);
            grid.Controls.Add(b, 2, row);
            browse = b;
            return t;
        }

        void BrowseRar()
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Title = "Pick the .rar or .zip file";
                d.Filter = "RAR and ZIP archives (*.rar;*.zip)|*.rar;*.zip|All files (*.*)|*.*";
                if (d.ShowDialog(this) == DialogResult.OK)
                {
                    txtRar.Text = d.FileName;
                    if (!destEdited || txtDest.Text.Trim().Length == 0)
                    {
                        string dir = Path.GetDirectoryName(d.FileName);
                        txtDest.Text = Path.Combine(dir, Path.GetFileNameWithoutExtension(d.FileName));
                        destEdited = false;
                    }
                }
            }
        }

        void BrowseDest()
        {
            using (FolderBrowserDialog d = new FolderBrowserDialog())
            {
                d.Description = "Pick an empty (or new) folder to extract into";
                d.ShowNewFolderButton = true;
                if (d.ShowDialog(this) == DialogResult.OK) { txtDest.Text = d.SelectedPath; destEdited = true; }
            }
        }

        void BrowseDll()
        {
            using (OpenFileDialog d = new OpenFileDialog())
            {
                d.Title = "Pick 7z.dll (in your 7-Zip folder)";
                d.Filter = "7z.dll|7z.dll|DLL files (*.dll)|*.dll";
                if (d.ShowDialog(this) == DialogResult.OK) txtDll.Text = d.FileName;
            }
        }

        void SetBusy(bool busy)
        {
            txtRar.Enabled = txtDest.Enabled = txtDll.Enabled = !busy;
            btnRar.Enabled = btnDest.Enabled = btnDll.Enabled = !busy;
            chkTest.Enabled = chkDelete.Enabled = !busy;
            btnStart.Enabled = !busy;
        }

        void RunOnUi(Action a)
        {
            try
            {
                if (IsDisposed || !IsHandleCreated) return;
                BeginInvoke(a);
            }
            catch (InvalidOperationException) { } // also covers ObjectDisposedException (form already closed)
        }

        void StartClicked()
        {
            SetBusy(true);
            txtLog.Text = "";
            bar.Style = ProgressBarStyle.Marquee;
            lblStatus.Text = "Checking the archive and your free space...";
            lblStats.Text = "";
            string a = txtRar.Text, d = txtDest.Text, u = txtDll.Text;
            Thread t = new Thread(delegate()
            {
                Preflight p = Engine.Check(a, d, u);
                RunOnUi(delegate { OnChecked(p); });
            });
            t.IsBackground = true;
            t.Start();
        }

        void OnChecked(Preflight p)
        {
            bar.Style = ProgressBarStyle.Continuous;
            bar.Value = 0;
            if (p.Error != null)
            {
                lblStatus.Text = "Can't start.";
                MessageBox.Show(this, p.Error, "Archive Space Saver", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                SetBusy(false);
                return;
            }

            string arc = Util.ArcName(p.Archive);
            StringBuilder msg = new StringBuilder();
            msg.AppendLine("Extract this " + arc + " now?");
            msg.AppendLine();
            msg.AppendLine("From:  " + p.Archive + "  (" + Util.Size(p.ArchiveBytes) + ")");
            msg.AppendLine("Into:  " + p.Dest);
            msg.AppendLine("Contents:  " + p.FileCount.ToString("N0", CultureInfo.CurrentCulture) + " files, " + Util.Size(p.UnpackedBytes) + " unpacked");
            msg.AppendLine("Free space on " + p.DestRoot + ":  " + Util.Size(p.FreeBytes) + "  (needs about " + Util.Size(p.NeededFree) + ")");
            if (p.RenamedCount > 0)
            {
                msg.AppendLine();
                msg.AppendLine(p.RenamedCount.ToString("N0", CultureInfo.CurrentCulture) + (p.RenamedCount == 1 ? " name uses" : " names use") +
                               " characters Windows doesn't allow, so they get \"_\" instead, e.g.");
                msg.AppendLine(p.RenamedExample);
            }
            msg.AppendLine();
            if (p.SameVolume)
            {
                if (chkTest.Checked)
                    msg.AppendLine("First it tests the whole archive. Nothing is touched unless every file checks out OK.");
                else
                    msg.AppendLine("Not testing first: if the archive turns out to be damaged part-way, the " + arc + " will already be partly used up.");
                msg.AppendLine("The " + arc + " is used up while it extracts. If you stop half-way, that " + arc + " can't be finished and you'd have to download it again.");
                if (p.Solid) msg.AppendLine("(This is a \"solid\" archive, so the space estimate is cautious and it can't be resumed once started.)");
            }
            else
                msg.AppendLine("The extract folder is on a different drive from the " + arc + ", so freeing space as it goes wouldn't help. " +
                               "It extracts normally and leaves the " + arc + " untouched" +
                               (chkDelete.Checked ? " (deleting it at the end only if everything extracted OK)." : "."));
            msg.AppendLine();
            msg.AppendLine("Continue?");
            if (MessageBox.Show(this, msg.ToString(), "Archive Space Saver", MessageBoxButtons.YesNo, MessageBoxIcon.Question, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
            {
                lblStatus.Text = "Cancelled before starting. Nothing was changed.";
                SetBusy(false);
                return;
            }

            engine = new Engine(p, chkDelete.Checked, p.SameVolume, chkTest.Checked);
            running = true;
            btnCancel.Enabled = true;
            bar.Style = ProgressBarStyle.Marquee;
            lblStatus.Text = "Starting...";
            timer.Start();
            Engine e = engine;
            Thread t = new Thread(delegate()
            {
                RunResult r = e.Run();
                RunOnUi(delegate { OnFinished(r); });
            });
            t.IsBackground = true;
            t.Name = "extract";
            t.Start();
        }

        void CancelClicked()
        {
            if (!running || engine == null) return;
            DialogResult r = MessageBox.Show(this,
                "Stop extracting?\n\nThe part already extracted stays in the folder" + (ArchiveStillWhole()
                    ? ". Nothing has been taken out of the " + engine.Arc + " so far, so it can still be extracted again later."
                    : ", but this " + engine.Arc + " can no longer be extracted completely."),
                "Archive Space Saver", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (r == DialogResult.Yes) { lblStatus.Text = "Stopping..."; engine.Cancel(); }
        }

        void OnClosing(object sender, FormClosingEventArgs e)
        {
            if (!running || engine == null) return;
            DialogResult r = MessageBox.Show(this,
                "Extraction is still running. Closing now will stop it" + (ArchiveStillWhole()
                    ? ". Nothing has been taken out of the " + engine.Arc + " so far."
                    : ", and this " + engine.Arc + " can no longer be extracted completely.") + "\n\nStop and close?",
                "Archive Space Saver", MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
            if (r != DialogResult.Yes) { e.Cancel = true; return; }
            engine.Cancel();
        }

        // True while no space has been taken out of the .rar (always, when extracting to another drive).
        bool ArchiveStillWhole()
        {
            return !engine.FreesSpace || engine.PunchedTo == 0;
        }

        void UpdateLive()
        {
            Engine e = engine;
            if (e == null || !running) return;
            long total = e.ArchiveSize;
            string file = e.CurrentFile;
            long alloc = e.AllocatedNow;
            long freed = (alloc >= 0) ? Math.Max(0, total - alloc) : 0;
            RunPhase phase = e.Phase;
            bool paused = e.WaitingForSpace;

            if ((phase == RunPhase.Testing || phase == RunPhase.Extracting) && total > 0)
            {
                long pos = phase == RunPhase.Testing ? e.TestPos : e.TrustedPos;
                bar.Style = ProgressBarStyle.Continuous;
                bar.Value = (int)Math.Max(0, Math.Min(1000L, pos * 1000L / total));
                string pct = (pos * 100.0 / total).ToString("0.0", CultureInfo.InvariantCulture) + "%";
                if (paused)
                    lblStatus.Text = "PAUSED: the drive is full. Free up some space on " + e.DestDrive + " and it carries on by itself (it needs " +
                                     Util.Size(Engine.ResumeFree) + " free). Nothing is lost while it waits.";
                else if (phase == RunPhase.Testing)
                    lblStatus.Text = "Testing " + pct + " (nothing is changed yet)  -  " + file;
                else
                    lblStatus.Text = "Extracting " + pct + "  -  " + file;
            }
            else
            {
                bar.Style = ProgressBarStyle.Marquee;
                lblStatus.Text = phase == RunPhase.Finishing ? "Finishing up..." : "Opening the archive...";
            }
            lblStatus.ForeColor = paused ? WarnColor : SystemColors.ControlText;
            string title = paused ? "PAUSED (drive full) - Archive Space Saver" : "Archive Space Saver"; // shows on the taskbar too
            if (Text != title) Text = title;

            lblStats.Text = "Time: " + Util.Duration(e.Elapsed) +
                            (phase == RunPhase.Testing ? "     Files checked: " + e.FilesTested.ToString(CultureInfo.CurrentCulture)
                                                       : "     Files done: " + e.FilesDone.ToString(CultureInfo.CurrentCulture)) +
                            (e.FreesSpace ? "     Space given back from the " + e.Arc + " so far: " + Util.Size(freed)
                                          : "     The " + e.Arc + " isn't touched (extracting to another drive)");
        }

        static void AppendItemErrors(StringBuilder s, RunResult r)
        {
            int shown = 0;
            foreach (string line in r.ItemErrors) { if (shown++ >= 8) break; s.AppendLine("- " + line); }
            if (r.ItemErrors.Count > 8) s.AppendLine("... and " + (r.ItemErrors.Count - 8) + " more (see Messages).");
        }

        void OnFinished(RunResult r)
        {
            timer.Stop();
            running = false;
            btnCancel.Enabled = false;
            bar.Style = ProgressBarStyle.Continuous;
            Text = "Archive Space Saver";
            lblStatus.ForeColor = SystemColors.ControlText;
            SetBusy(false);

            string arc = engine != null ? engine.Arc : "archive";
            StringBuilder s = new StringBuilder();
            MessageBoxIcon icon;
            if (r.StartFailed)
            {
                s.AppendLine("Couldn't start the extraction.");
                s.AppendLine(r.Problem ?? "Unknown problem.");
                icon = MessageBoxIcon.Error;
                lblStatus.Text = "Failed to start.";
            }
            else if (r.Cancelled)
            {
                s.AppendLine(r.ArchiveIntact
                    ? "Stopped. What was already extracted is in the folder. Nothing was taken out of the " + arc + ", so it can still be extracted again (into an empty folder)."
                    : "Stopped. What was already extracted is in the folder, but this " + arc + " can no longer be extracted completely.");
                icon = MessageBoxIcon.Warning;
                lblStatus.Text = "Stopped.";
            }
            else if (r.TestFailed)
            {
                s.AppendLine("The test found problems, so nothing was extracted and the " + arc + " wasn't changed.");
                if (r.Problem != null) s.AppendLine(r.Problem);
                AppendItemErrors(s, r);
                s.AppendLine("Try downloading it again, or extract it with 7-Zip or WinRAR to save what can be saved.");
                icon = MessageBoxIcon.Error;
                lblStatus.Text = "The test found problems. Nothing was changed.";
            }
            else if (r.Success)
            {
                bar.Value = bar.Maximum;
                s.AppendLine("Done - " + r.FilesExtracted.ToString("N0", CultureInfo.CurrentCulture) + " files extracted and checked OK.");
                s.AppendLine("Time: " + Util.Duration(r.Elapsed));
                if (r.ArchiveDeleted) s.AppendLine("The leftover " + arc + " was deleted.");
                else if (r.DeleteNote != null) s.AppendLine(r.DeleteNote);
                else s.AppendLine("The leftover " + arc + " (mostly empty now) was kept; you can delete it.");
                icon = MessageBoxIcon.Information;
                lblStatus.Text = "Done.";
            }
            else
            {
                s.AppendLine("Finished with problems. The " + arc + " was NOT deleted" +
                             (r.ArchiveIntact ? ", and nothing was taken out of it, so it's still complete." : "."));
                if (r.Problem != null) s.AppendLine(r.Problem);
                AppendItemErrors(s, r);
                s.AppendLine("(" + r.FilesExtracted.ToString("N0", CultureInfo.CurrentCulture) + " files were extracted fine.)");
                icon = MessageBoxIcon.Error;
                lblStatus.Text = "Finished with problems.";
            }
            if (r.PunchProblem != null) s.AppendLine("\n" + r.PunchProblem);

            StringBuilder log = new StringBuilder();
            foreach (string line in r.ItemErrors) log.AppendLine(line);
            if (!string.IsNullOrEmpty(r.Log)) log.AppendLine(r.Log);
            log.Append(s.ToString());
            txtLog.Text = log.ToString().Replace("\r\n", "\n").Replace("\n", "\r\n");
            lblStats.Text = "Time: " + Util.Duration(r.Elapsed) + "     Space given back from the " + arc + ": " + Util.Size(r.FreedBytes);
            MessageBox.Show(this, s.ToString(), "Archive Space Saver", MessageBoxButtons.OK, icon);
        }
    }
#endif

    static class Program
    {
#if CLI
        // Test harness build (not shipped): ArchiveSpaceSaverCli.exe, see the usage line below.
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length == 1 && args[0] == "--find-dll") { Console.WriteLine("found: " + Util.FindSevenZipDll()); return 0; }
            if (args.Length < 3)
            {
                Console.WriteLine("usage: <rar> <dest> <7z.dll> [--keep] [--check] [--test] [--test-only] [--cancel=<sec>] [--fail-create=<name>] " +
                                  "[--full-at=<bytes>] [--other-drive] [--expect-extra]\n       --find-dll");
                return 64;
            }
            bool keep = Array.IndexOf(args, "--keep") >= 0;
            bool checkOnly = Array.IndexOf(args, "--check") >= 0;
            bool test = Array.IndexOf(args, "--test") >= 0;
            if (Array.IndexOf(args, "--test-only") >= 0) { test = true; Engine.TestOnly = true; }
            bool otherDrive = Array.IndexOf(args, "--other-drive") >= 0; // run as if the extract folder were on another drive
            int cancelAfter = -1;
            foreach (string a in args)
            {
                if (a.StartsWith("--cancel=", StringComparison.Ordinal)) cancelAfter = int.Parse(a.Substring(9));
                if (a.StartsWith("--fail-create=", StringComparison.Ordinal)) ExtractCallback.TestFailCreate = a.Substring(14);
                if (a.StartsWith("--full-at=", StringComparison.Ordinal)) Engine.TestFullAt = long.Parse(a.Substring(10));
            }
            Preflight p = Engine.Check(args[0], args[1], args[2]);
            Console.WriteLine("CHECK: error=" + (p.Error ?? "none"));
            Console.WriteLine("  archive=" + p.ArchiveBytes + " unpacked=" + p.UnpackedBytes + " files=" + p.FileCount +
                " peakExtra=" + p.PeakExtra + " needed=" + p.NeededFree + " free=" + p.FreeBytes + " same=" + p.SameVolume + " solid=" + p.Solid +
                " renamed=" + p.RenamedCount + (p.RenamedExample != null ? " e.g. " + p.RenamedExample : ""));
            if (p.Error != null) return 2;
            if (checkOnly) return 0;
            if (Array.IndexOf(args, "--expect-extra") >= 0) p.FileCount++; // pretend the check counted a file that won't come out
            Engine e = new Engine(p, !keep, p.SameVolume && !otherDrive, test);
            RunResult result = null;
            Thread t = new Thread(delegate() { result = e.Run(); });
            t.Start();
            long minFree = long.MaxValue;
            string vol = Path.GetDirectoryName(p.Archive);
            long startFree = Util.FreeSpace(vol);
            int tick = 0;
            while (t.IsAlive)
            {
                Thread.Sleep(100);
                if (cancelAfter >= 0 && e.Elapsed.TotalSeconds >= cancelAfter) e.Cancel();
                long f = Util.FreeSpace(vol);
                if (f >= 0 && f < minFree) minFree = f;
                if (++tick % 10 == 0)
                    Console.WriteLine("t=" + e.Elapsed.TotalSeconds.ToString("0.0") + "s " + e.Phase + (e.WaitingForSpace ? " WAITING-FOR-SPACE" : "") +
                        " tested=" + e.FilesTested + " testPos=" + Util.Size(e.TestPos) + " trusted=" + Util.Size(e.TrustedPos) +
                        " punched=" + Util.Size(e.PunchedTo) + " alloc=" + Util.Size(e.AllocatedNow) + " free=" + Util.Size(f) + " files=" + e.FilesDone + " cur=" + e.CurrentFile);
            }
            Console.WriteLine("RESULT: success=" + result.Success + " cancelled=" + result.Cancelled + " startFailed=" + result.StartFailed +
                " testFailed=" + result.TestFailed +
                " problem=" + (result.Problem ?? "none") + " punchProblem=" + (result.PunchProblem ?? "none") +
                " files=" + result.FilesExtracted + " freed=" + Util.Size(result.FreedBytes) + " deleted=" + result.ArchiveDeleted +
                " intact=" + result.ArchiveIntact +
                " elapsed=" + result.Elapsed.TotalSeconds.ToString("0.0"));
            Console.WriteLine("PEAK USE above start: " + Util.Size(startFree - minFree));
            foreach (string s in result.ItemErrors) Console.WriteLine("ITEM ERROR: " + s);
            if (result.Log != null && result.Log.Length > 0) Console.WriteLine("LOG:\n" + result.Log);
            return result.Success ? 0 : 1;
        }
#else
        [STAThread]
        static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }
#endif
    }
}
