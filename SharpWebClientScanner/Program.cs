using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace SharpWebClientScanner
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool WaitNamedPipeA(string lpNamedPipeName, uint nTimeOut);

        static void Main(string[] args)
        {
            int threadCount = 5;
            List<string> targetHosts;
            string domainName = null;
            string fileName = null;
            string outputFileName = null;

            Console.WriteLine(@"
░█▀▀░█░█░█▀█░█▀▄░█▀█░░░█░█░█▀▀░█▀▄░░░█▀▀░█░░░▀█▀░█▀▀░█▀█░▀█▀░░░█▀▀░█▀▀░█▀█░█▀█░█▀█░█▀▀░█▀▄
░▀▀█░█▀█░█▀█░█▀▄░█▀▀░░░█▄█░█▀▀░█▀▄░░░█░░░█░░░░█░░█▀▀░█░█░░█░░░░▀▀█░█░░░█▀█░█░█░█░█░█▀▀░█▀▄
░▀▀▀░▀░▀░▀░▀░▀░▀░▀░░░░░▀░▀░▀▀▀░▀▀░░░░▀▀▀░▀▀▀░▀▀▀░▀▀▀░▀░▀░░▀░░░░▀▀▀░▀▀▀░▀░▀░▀░▀░▀░▀░▀▀▀░▀░▀
                                                                              By Mor David
");

            if (args.Length == 0)
            {
                Console.WriteLine("[X] Error: Provide target domain on the command line, use flag --domain or --file or --output.");
                return;
            }

            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i].Equals("--domain", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    {
                        domainName = args[i + 1];
                    }
                    else if (args[i].Equals("--file", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    {
                        fileName = args[i + 1];
                    }
                    else if (args[i].Equals("--output", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                    {
                        outputFileName = args[i + 1];
                    }
                }

                if (fileName != null)
                {
                    // Load hosts from the specified file
                    targetHosts = LoadHostsFromFile(fileName);
                }
                else
                {
                    // Get list of computers in the specified domain
                    targetHosts = GetComputersInDomain(domainName);
                }

                int tcIndex = Array.FindIndex(args, x => x.StartsWith("--tc", StringComparison.OrdinalIgnoreCase));
                if (tcIndex >= 0)
                {
                    threadCount = Int32.Parse(args[tcIndex + 1]);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("[X] Error parsing the arguments, please check and try again.");
                Console.WriteLine(e.Message);
                return;
            }

            // Set up StreamWriter for writing to the output file
            using (StreamWriter writer = outputFileName != null ? new StreamWriter(outputFileName) : null)
            {
                // Get WebDAV Status 
                Parallel.ForEach(targetHosts, new ParallelOptions { MaxDegreeOfParallelism = threadCount }, singleTarget =>
                {
                    string pipename = @"\\" + singleTarget + @"\pipe\DAV RPC SERVICE";
                    bool davActive = WaitNamedPipeA(pipename, 5000);

                    // Output to the console
                    if (davActive)
                    {
                        Console.WriteLine("[+] WebClient service is active on " + singleTarget);
                    }
                    else
                    {
                        Console.WriteLine("[x] Unable to reach DAV pipe on {0}, system is either unreachable or does not have WebClient service running", singleTarget);
                    }

                    // Output to the file if specified
                    if (outputFileName != null)
                    {
                        string outputString = davActive
                            ? $"[+] WebClient service is active on {singleTarget}"
                            : $"[x] Unable to reach DAV pipe on {singleTarget}, system is either unreachable or does not have WebClient service running";
                        writer.WriteLine(outputString);
                    }
                });
            }
        }
        private static List<string> LoadHostsFromFile(string fileName)
        {
            List<string> hosts = new List<string>();

            try
            {
                // Check if the file exists
                if (!File.Exists(fileName))
                {
                    Console.WriteLine("[X] Error: The specified file does not exist.");
                    return hosts;
                }

                // Read all lines from the file and add them to the hosts list
                string[] lines = File.ReadAllLines(fileName);

                foreach (string line in lines)
                {
                    // Add each line (host) to the hosts list after trimming whitespace
                    string trimmedLine = line.Trim();
                    if (!string.IsNullOrEmpty(trimmedLine))
                    {
                        hosts.Add(trimmedLine);
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("[X] Error reading file: " + ex.Message);
            }

            return hosts;
        }

        private static List<string> GetComputersInDomain(string domainName)
        {
            List<string> computers = new List<string>();
            using (DirectoryEntry rootEntry = new DirectoryEntry("LDAP://" + domainName))
            {
                using (DirectorySearcher searcher = new DirectorySearcher(rootEntry))
                {
                    searcher.Filter = "(objectClass=computer)";
                    searcher.PageSize = 1000;
                    foreach (object obj in searcher.FindAll())
                    {
                        string computerName = ((SearchResult)obj).GetDirectoryEntry().Name;
                        computers.Add(computerName.Split(new char[] { '=' })[1]);
                    }
                }
            }
            return computers;
        }
    }
}
