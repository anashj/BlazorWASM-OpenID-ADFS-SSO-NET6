using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BlazorWasmOpenIdADFS.Shared
{
    public class ClaimValue
    {
        public ClaimValue()
        {
        }

        public ClaimValue(string type, string value)
        {
            Type = type;
            Value = value;
        }

        public string Type { get; set; }

        public string Value { get; set; }
    }
}
