using System.Threading.Tasks;

namespace ConformanceTests
{
    public class Program
    {
        public static void Main(string[] args) => MainAsync().GetAwaiter().GetResult();

        public static async Task MainAsync()
        {
            await new CodeTests().Start();
        }
    }
}