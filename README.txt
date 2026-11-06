Archive Space Saver
===================

Extracts a .rar or .zip and gives the archive's disk space back as it goes. So a 50 GB download
needs about 50 GB free instead of 100 GB.

How to use it
  1. Double click ArchiveSpaceSaver.exe (no install, no admin needed)
  2. Pick the .rar or .zip, then pick an empty or new folder to extract into
  3. Click Start, read the message, click Yes

What you need
  - 64-bit 7-Zip installed (it uses 7-Zip's 7z.dll, found automatically)
  - The archive on an NTFS drive (the Windows default)

Stuff to know
  - The archive gets used up while it extracts. If you stop half way (cancel, crash, power cut)
    it cant be finished and you have to download it again.
  - The space saving only works if the extract folder is on the same drive as the archive.
    On a different drive it just extracts normally and leaves the archive alone.
  - It refuses to start with split archives (.part1.rar, .r00, .z01), password protected ones,
    damaged ones, ones that are still downloading, and ones another program is writing to.
  - By default it tests the whole archive first, so a damaged one is caught before anything is
    touched. Takes about twice as long, you can untick it.
  - If the drive fills up it pauses and carries on by itself once 512 MB is free again.
  - It never overwrites anything. The extract folder has to be empty or new.
  - Names Windows doesnt allow (like "Episode 1: Pilot.mkv") get a _ instead, same as 7-Zip.
  - It saves no settings and writes no registry keys or temp files.

To rebuild it yourself just run build.cmd, it uses the C# compiler that comes with Windows.
