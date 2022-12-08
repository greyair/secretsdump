using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace RegHive
{
    internal class LocalOps
    {
        public static RegistryHive? GetHiveDump(string dumpfileName)
        {
            if (File.Exists(dumpfileName))
            {
                using (FileStream stream = File.OpenRead(dumpfileName))
                {
                    using (BinaryReader reader = new BinaryReader(stream))
                    {
                        reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
                        RegistryHive hive = new RegistryHive(reader);
                        return hive;
                    }
                }
            }
            else
            {
                Console.WriteLine("[X] Error unable to access hive dump file on the remote system at {0} -- manual cleanup may be needed", dumpfileName);
                return null;
            }
        }
        public static NodeKey GetNodeKey(RegistryHive hive, string path)
        {

            NodeKey node = null;
            string[] paths = path.Split('\\');

            foreach (string ch in paths)
            {
                bool found = false;
                if (node == null)
                    node = hive.RootKey;

                foreach (NodeKey child in node.ChildNodes)
                {
                    if (child.Name == ch)
                    {
                        node = child;
                        found = true;
                        break;
                    }
                }
                if (found == false)
                {
                    return null;
                }
            }
            return node;
        }

        public static ValueKey GetValueKey(RegistryHive hive, string path)
        {

            string keyname = path.Split('\\').Last();
            path = path.Substring(0, path.LastIndexOf('\\'));

            NodeKey node = GetNodeKey(hive, path);

            return node.ChildValues.SingleOrDefault(v => v.Name == keyname);
        }
    }
}
