using CSAF_Tool.CSAFArchive;

namespace CSAF_Tool
{
    internal class Program
    {
        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage:");
                Console.WriteLine("Extract resource : Tool_Name <archive path> [output directory]");

                return;
            }

            string sourceArchive = args[0];

            string outputDirectory = args.Length >= 2 ? args[1] : sourceArchive + "_extract";

            Csaf.ExtractResource(sourceArchive, outputDirectory);
        }
    }
}
