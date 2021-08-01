using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualBasic;

namespace PoqDlg_Decrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 0)
                return;
            if (Path.GetExtension(args[0]) == ".dlg")
                DlgFile(args[0]);
            else if (Path.GetExtension(args[0]) == ".csv")
            {
                if (File.Exists(Path.GetDirectoryName(args[0]) + "\\" + Path.GetFileNameWithoutExtension(args[0]) + ".dlg"))
                    CSVFile(args[0]);
                else
                    return;
            }
            else
                return;
        }

        static void DlgFile(string path)
        {
            BinaryReader rd = new BinaryReader(File.OpenRead(path));
            rd.BaseStream.Seek(0x2C, SeekOrigin.Begin);
            rd.ReadUInt32();
            rd.BaseStream.Seek(0x20, SeekOrigin.Current);
            uint _tableID = rd.ReadUInt32();
            rd.ReadBytes(4);
            uint _numLine = rd.ReadUInt32();
            rd.BaseStream.Seek(_tableID, SeekOrigin.Begin);
            long _curPos = 0;
            List<int> ID = new List<int>();
            using (CsvFileWriter wt = new CsvFileWriter(Path.GetDirectoryName(path) + "\\" + Path.GetFileNameWithoutExtension(path) + ".csv"))
            {
                for (int i = 0; i < _numLine; i++)
                {
                    int _idText = rd.ReadInt32(); //ID
                    uint _pos = rd.ReadUInt32();//position
                    if (!ID.Contains(_idText))
                    {
                        ID.Add(_idText);
                        _curPos = rd.BaseStream.Position;
                        rd.BaseStream.Seek(_pos, SeekOrigin.Begin);
                        uint _len = rd.ReadUInt32();
                        byte[] _txtData = rd.ReadBytes((int)_len);
                        wt.WriteRow(Dec(_txtData));
                        rd.BaseStream.Seek(_curPos, SeekOrigin.Begin);
                    }
                }
            }
        }

        static void CSVFile(string path)
        {
            BinaryReader rd = new BinaryReader(File.OpenRead(Path.GetDirectoryName(path) + "\\" + Path.GetFileNameWithoutExtension(path) + ".dlg"));
            BinaryWriter wt = new BinaryWriter(File.Create(Path.GetDirectoryName(path) + "\\" + Path.GetFileNameWithoutExtension(path) + "_new.dlg"));
            wt.Write(rd.ReadBytes(0x50));
            uint _tableID = rd.ReadUInt32();
            wt.Write(_tableID);
            wt.Write(rd.ReadBytes(4));
            uint _numLine = rd.ReadUInt32();
            wt.Write(_numLine);
            wt.Write(rd.ReadBytes((int)_tableID - 0x5C));
            long _posID = wt.BaseStream.Position;
            long _posTxt = _posID + _numLine * 8;
            long _sizeLast = _posTxt;
            using (CsvFileReader reader = new CsvFileReader(path))
            {
                CsvRow row = new CsvRow();
                while (reader.ReadRow(row))
                {
                    wt.Write(rd.ReadUInt32());
                    wt.Write((int)_posTxt);
                    byte[] outData = Enc(row);
                    _posID = wt.BaseStream.Position;
                    rd.ReadUInt32();
                    wt.BaseStream.Seek(_posTxt, SeekOrigin.Begin);
                    wt.Write(outData.Length);
                    wt.Write(outData);
                    _posTxt = wt.BaseStream.Position;
                    wt.BaseStream.Seek(_posID, SeekOrigin.Begin);
                }
            }
            wt.BaseStream.Seek(wt.BaseStream.Length, SeekOrigin.Begin);
            wt.Write((int)(_posTxt - _sizeLast));
            wt.Close();
            rd.Close();
        }

        static byte[] Enc(CsvRow row)
        {
            List<byte> outData = new List<byte>();
            for(int i = 0; i < 5; i++)
            {
                outData.AddRange(Xor(BitConverter.GetBytes(int.Parse(row[i]))));
            }
            for(int i = 0; i < 3; i++)
            {
                outData.AddRange(Xor(BitConverter.GetBytes(int.Parse(row[i * 2 + 5]))));
                byte[] _comp = StringToByteArray(row[i * 2 + 6]);
                outData.AddRange(Xor(BitConverter.GetBytes(_comp.Length)));
                outData.AddRange(Xor(_comp));
            }
            outData.AddRange(Xor(BitConverter.GetBytes(int.Parse(row[11]))));
            StringBuilder bd = new StringBuilder(row[12]);
            bd.Replace("[r]", "\r");
            bd.Replace("[n]", "\n");
            bd.Replace("[t]", "\t");
            bd.Replace("[0]", "\0");
            byte[] _txt = Encoding.Default.GetBytes(bd.ToString());
            outData.AddRange(Xor(BitConverter.GetBytes(_txt.Length)));
            outData.AddRange(Xor(_txt));
            outData.AddRange(Xor(BitConverter.GetBytes(outData.Count + 4)));
            return outData.ToArray();
        }

        static CsvRow Dec(byte[] input)
        {
            CsvRow row = new CsvRow();
            byte[] outBuffer = new byte[input.Length];
            BinaryReader rd = new BinaryReader(new MemoryStream(input));
            int count = IntConvert(rd);
            row.Add(count.ToString());
            for (int i = 0; i < count; i++)
            {
                int _key = IntConvert(rd);
                row.Add(_key.ToString());
                switch (_key)
                {
                    case 0x64:
                        row.Add(IntConvert(rd).ToString());
                        break;
                    case 0x65:
                        row.Add(IntConvert(rd).ToString());
                        break;
                    case 0x66:
                        row.Add(BitConverter.ToString(ArrConvert(rd)).Replace("-", " "));
                        break;
                    case 0x67:
                        row.Add(BitConverter.ToString(ArrConvert(rd)).Replace("-", " "));
                        break;
                    case 0x68:
                        row.Add(BitConverter.ToString(ArrConvert(rd)).Replace("-", " "));
                        break;
                    case 0x69:
                        byte[] _txtOut = ArrConvert(rd);
                        StringBuilder bd = new StringBuilder(Encoding.Default.GetString(_txtOut));
                        bd.Replace("\r", "[r]");
                        bd.Replace("\n", "[n]");
                        bd.Replace("\t", "[t]");
                        bd.Replace("\0", "[0]");
                        row.Add(bd.ToString());
                        break;
                    default:
                        continue;
                }
            }
            IntConvert(rd);
            return row;
        }
        
        static int IntConvert(BinaryReader rd)
        {
            byte[] buffer = rd.ReadBytes(4);
            int outInt = BitConverter.ToInt32(Xor(buffer), 0);
            return outInt;
        }
 
        static byte[] ArrConvert(BinaryReader rd)
        {
            int def = IntConvert(rd);
            byte[] inBuffer = rd.ReadBytes(def);
            byte[] outBuffer = Xor(inBuffer);
            return outBuffer;
        }

        static byte[] Xor(byte[] input)
        {
            byte[] newByte = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
            {
                byte sg = input[i];
                sg ^= (byte)(input.Length - i - 0x57);
                newByte[i] = sg;
            }
            return newByte;
        }

        static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length).Where(x => x % 2 == 0).Select(x => Convert.ToByte(hex.Substring(x, 2), 16)).ToArray();
        }
    }
}
