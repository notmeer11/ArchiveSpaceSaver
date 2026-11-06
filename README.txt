RAR Space Saver
===============

Extracts a single .rar or .zip and gives the archive's disk space back while it works, so a
50 GB download needs about 50 GB free instead of 100 GB.

Use it:
  1. Double-click RarSpaceSaver.exe (no install, no admin rights).
  2. Pick the .rar or .zip, pick an EMPTY or NEW folder to extract into, click Start.
  3. Read the confirmation, click Yes.

Needs (all already on your PC):
  - 64-bit 7-Zip (it uses 7-Zip's 7z.dll; found automatically wherever 7-Zip is installed)
  - The archive on an NTFS drive (the Windows default)

Good to know:
  - The archive is USED UP while it extracts. If you stop half-way (Cancel, crash, power cut),
    it can't be finished and you have to download it again.
  - The space saving only works when the extract folder is on the same drive as the archive.
    If it's on another drive, it extracts normally and leaves the archive untouched.
  - Refused before anything is touched: split sets (.part1.rar / .r00 / .z01), password-
    protected archives, archives 7-Zip reports as damaged or cut short, an archive with missing
    pieces (still downloading in a torrent client, or used up by an earlier stopped run), an
    archive another program is still writing to, and archives whose file names would clash on
    Windows.
  - For a .zip it also checks that the files inside are stored in the order they get extracted,
    with no big unused stretches in between (true for practically every zip). If not, it
    refuses, unless the extract folder is on another drive.
  - Names Windows doesn't allow (like "Episode 1: Pilot.mkv") are saved with "_" instead, the
    same way 7-Zip does it. The confirmation tells you when this happens.
  - "Test the whole archive before touching it" (on by default) reads and checks every file
    first. If anything is damaged, it stops with the archive untouched. It takes about twice as
    long; untick it to skip, but then damage is only found part-way, when the archive is already
    partly used up.
  - If the drive fills up during extraction (another download, Windows Update...), it pauses
    instead of failing and carries on by itself once 512 MB is free again. Nothing is lost.
  - It refuses to start unless there is enough free space for the whole job.
  - It never overwrites: the extract folder must be empty or new.
  - A few rare RAR features (file-reference/dedupe records that point back at earlier data)
    can't be extracted this way; the app stops with a message instead of writing bad files.
  - It writes no settings, registry keys or temp files, and installs nothing. (It only reads
    the registry to find where 7-Zip is installed.)

Rebuild from source: run build.cmd (uses the C# compiler that ships with Windows).
