// See https://aka.ms/new-console-template for more information

using System.Runtime.InteropServices;

namespace SpeedTest
{
    using Args = System.Collections.Generic.Dictionary<string, int>;
    
    static class Program
    {
        [DllImport("speed_test_lib.so", EntryPoint="run_speed_test", CharSet = CharSet.Ansi, SetLastError = true, CallingConvention=CallingConvention.Cdec‌​l)]
        private static extern int run_speed_test(int async_jobs, int seconds, int cipher, string cipherName);

        private static readonly IList<int> rsa_keys = new List<int>{512, 1024, 2048, 3072, 4096, 7680, 15360};
        private static readonly string _async_jobs = "async_jobs";
        private static readonly string _seconds = "seconds";
        private static readonly string _rsa = "rsa";
        
        static int Main(string[] argv)
        {
            Args args = new Args();

            if(!ParseArgs(argv, ref args))
            {
                Console.WriteLine("Usage:");
                Console.WriteLine($"\tspeed_test {_async_jobs}=num_jobs {_seconds}=time_in_seconds {_rsa}[bits]\n");
                Console.WriteLine("\tnum_jobs\t-> [0-99999] - Enable async mode and start specified number of jobs. Use 0 for running in sync mode");
                Console.WriteLine("\ttime_in_seconds\t-> Run the test for specified amount of seconds.");
                Console.Write("\tbits\t\t-> [");

                foreach(var bits in rsa_keys) Console.Write($"{bits}, ");

                Console.WriteLine("\b\b]\n\n");
                return -1;
            }

            string cipherName = _rsa + args[_rsa];

            run_speed_test(args[_async_jobs], args[_seconds], args[_rsa], cipherName.ToUpper());

            return 0;
        }

        static bool ParseArgs(string[] argv, ref Args args)
        {
            if(argv.Count() == 0 || argv.Count() != 3) return false;

            for(int i = 0; i < argv.Count(); ++i)
            {
                string arg = argv[i];
                string key = string.Empty;
                int value = 0;

                if(arg.Substring(0, 3) == _rsa)
                {
                    try
                    {
                        value = int.Parse(arg.Substring(3));

                        if(!rsa_keys.Contains(value)) return false;

                        args[_rsa] = value;
                    }
                    catch(Exception)
                    {
                        return false;
                    }
                }
                else
                {
                    var equal_sign = arg.IndexOf('=');

                    if(equal_sign == -1) return false;

                    key = arg.Substring(0, equal_sign);
                    
                    try
                    {
                        value = int.Parse(arg.Substring(equal_sign + 1));

                        if(value < 0) return false;
                    }
                    catch(Exception)
                    {
                        return false;
                    }

                    if(key != _async_jobs && key != _seconds) return false;

                    if(key == _async_jobs && value > 99999) return false;

                    args[key] = value;        
                }
            }

            return true;
        }
    }
}