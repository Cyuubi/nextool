using CyuNEX.PRUDP;
using CyuNEX.Utilities;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NEXTool
{
    public partial class frmMain : Form
    {
        class Message
        {
            public bool Source { get; private set; }
            public string Data { get; private set; }

            public Message(bool source, string data)
            {
                Source = source;
                Data = data;
            }
        }

        private List<Message> _messages;

        private V0_Packet _packet;

        public frmMain()
        {
            _messages = new List<Message>();

            _packet = new V0_Packet("ridfebb9");

            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (openFileDialog1.ShowDialog() == DialogResult.OK)
            {
                listBox1.Items.Clear();

                var lines = File.ReadAllLines(openFileDialog1.FileName);

                // loop thru lines...
                foreach (var line in lines)
                {
                    var source = line.Contains(" => ");
                    var split = source ? line.Split(" => ") : line.Split(" <= ");
                    var data = split[1];

                    _messages.Add(new Message(source, data));
                }

                // iterate over messages, so its in order.
                foreach (var message in _messages)
                {
                    listBox1.Items.Add($"[{(message.Source ? "C" : "S")}] {message.Data}");
                }
            }
        }

        private byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        private void listBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (_packet != null)
            {
                _packet.ParseRaw(StringToByteArray(_messages[listBox1.SelectedIndex].Data));

                label13.Text = $"SrcType: {_packet.SourceType}";
                label3.Text = $"Src: {_packet.Source}";
                label14.Text = $"DstType: {_packet.DestinationType}";
                label4.Text = $"Dst: {_packet.Destination}";
                textBox1.Text = _packet.Flags.ToString();
                label6.Text = $"Type: {_packet.Type}";
                label7.Text = $"SessionId: {_packet.SessionId}";
                label8.Text = $"SequenceId: {_packet.SequenceId}";
                label9.Text = $"ConnectionSignature: {_packet.ConnectionSignature}";
                label10.Text = $"FragmentId: {_packet.FragmentId}";
                label11.Text = $"PayloadSize: {_packet.Payload.Length}";
            }
        }

        private void button2_Click(object sender, EventArgs e)
        {
            if (_packet != null && saveFileDialog1.ShowDialog() == DialogResult.OK)
            {
                // copypasting code is my signature move
                if (saveFileDialog1.FileName != string.Empty)
                {
                    var stream = (FileStream)saveFileDialog1.OpenFile();

                    stream.Write(_packet.Payload);
                    stream.Close();
                }
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if (_packet != null && saveFileDialog1.ShowDialog() == DialogResult.OK)
            {
                // copypasting code is my signature move
                if (saveFileDialog1.FileName != string.Empty)
                {
                    var stream = (FileStream)saveFileDialog1.OpenFile();

                    stream.Write(RC4.Decrypt(Encoding.ASCII.GetBytes(textBox2.Text), _packet.Payload));
                    stream.Close();
                }
            }
        }
    }
}
