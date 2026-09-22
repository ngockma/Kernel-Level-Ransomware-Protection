using System;
using System.Diagnostics;
using System.IO;
using System.Threading;

internal static class QuarantineTestStub
{
    private static int Main(string[] args)
    {
        Console.WriteLine("STUB_READY PID=" + Process.GetCurrentProcess().Id);
        Console.Out.Flush();

        if (args.Length == 0)
        {
            return 0;
        }

        Thread.Sleep(2000);

        try
        {
            File.AppendAllText(args[0], "GUARDIAN_PHASE7_TEST_WRITE");
            return 2;
        }
        catch (UnauthorizedAccessException)
        {
            Thread.Sleep(TimeSpan.FromSeconds(30));
            return 3;
        }
        catch (IOException)
        {
            Thread.Sleep(TimeSpan.FromSeconds(30));
            return 4;
        }
    }
}
