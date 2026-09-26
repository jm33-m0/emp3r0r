using SMBLibrary.Client;
using SMBLibrary;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace RemotePipeList
{
    internal class Program
    {
        static void Main(string[] args)
        {
            string target = null;
            string username = null;
            string password = null;

            if (args.Length == 0)
            {
                Console.WriteLine("RemotePipeList.exe <targetIP> <username> <password>");
                return;
            }
            if (args.Length == 3) {
                target = args[0];
                username = args[1];
                password = args[2];
            } 
            else 
            {
                Console.WriteLine("invalid arguments");
                return;
            }

            string domain = String.Empty;

            if (username != null)
            {
                if (username.Contains("\\"))
                {
                    var userdom = username.Split(new[] { '\\' }, 2);
                    if (userdom.Length == 2)
                    {
                        domain = userdom[0];
                        username = userdom[1];
                    }
                }
            }

            SMB2Client client = new SMB2Client();
            bool isConnected = client.Connect(target, SMBTransportType.DirectTCPTransport);
            if (isConnected)
            {
                NTStatus status = client.Login(domain, username, password, AuthenticationMethod.NTLMv2);
                if (status == NTStatus.STATUS_SUCCESS)
                {
                    Console.WriteLine("[+] Authenticate successful");

                    ISMBFileStore fileStore = client.TreeConnect("IPC$", out status);
                    if (status == NTStatus.STATUS_SUCCESS)
                    {
                        Console.WriteLine("[+] Connected to \\\\" + target+ "\\IPC$");

                        object directoryHandle;
                        FileStatus fileStatus;
                        status = fileStore.CreateFile(out directoryHandle, out fileStatus, String.Empty, AccessMask.GENERIC_READ, FileAttributes.Directory, ShareAccess.Read | ShareAccess.Write, CreateDisposition.FILE_OPEN, CreateOptions.FILE_DIRECTORY_FILE, null);
                        if (status == NTStatus.STATUS_SUCCESS)
                        {
                            Console.WriteLine("[+] Pipe listing:");

                            List<QueryDirectoryFileInformation> fileList;
                            status = fileStore.QueryDirectory(out fileList, directoryHandle, "*", FileInformationClass.FileDirectoryInformation);
                            status = fileStore.CloseFile(directoryHandle);

                            if (status == NTStatus.STATUS_SUCCESS)
                            {
                                foreach (var file in fileList)
                                {
                                    var fic = new FileDirectoryInformation(file.GetBytes(), 0);
                                    Console.WriteLine("    " + fic.FileName);
                                }
                            }
                            else
                            {
                                Console.WriteLine("Error: {0}", status);
                            }
                        }
                        else
                        {
                            Console.WriteLine("Error: {0}", status);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Error: {0}", status);
                    }

                    client.Logoff();
                }
                else
                {
                    Console.WriteLine("Error: {0}", status);
                }
                client.Disconnect();
            }
            else
            {
                Console.WriteLine("Couldn't connect.");
            }
        }
    }
}
