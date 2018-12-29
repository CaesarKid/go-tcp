package main

import (
	"strconv"
	"strings"
)

//Tcp头部
/**






	0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Source address                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Destination address                      |       tcp 伪首部
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Zeros      |     Protocol  |        TCP Length             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |           |U|A|P|R|S|F|                               |
   | Offset| Reserved  |R|C|S|S|Y|I|            Window             |       tcp首部
   |       |           |G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
TCP伪首部共有12字节，包含IP首部的一些字段，有如下信息：32位源IP地址、32位目的IP地址、8位保留字节(置0)、8位传输层协议号(TCP是6，UDP是17)、16位TCP报文长度(TCP首部+数据)。

TCP首部
●源、目标端口号字段：占16比特。TCP协议通过使用"端口"来标识源端和目标端的应用进程。端口号可以使用0到65535之间的任何数字。在收到服务请求时，操作系统动态地为客户端的应用程序分配端口号。在服务器端，每种服务在"众所周知的端口"（Well-Know Port）为用户提供服务。
●顺序号字段：占32比特。用来标识从TCP源端向TCP目标端发送的数据字节流，它表示在这个报文段中的第一个数据字节。
●确认号字段：占32比特。只有ACK标志为1时，确认号字段才有效。它包含目标端所期望收到源端的下一个数据字节。
●头部长度字段：占4比特。给出头部占32比特的数目。没有任何选项字段的TCP头部长度为20字节（5x32=160比特）；最多可以有60字节的TCP头部。
●数据偏移：占4位，它指出TCP报文段的数据起始处距离TCP报文段的起始处有多远，这个字段实际上是指出TCP报文段的首部长度
●保留：占6位。保留为今后使用，目前置为0
●标志位字段（U、A、P、R、S、F）：占6比特。各比特的含义如下：
    ◆URG：紧急指针（urgent pointer）有效。
    ◆ACK：确认序号有效。
    ◆PSH：接收方应该尽快将这个报文段交给应用层。
    ◆RST：重建连接。
    ◆SYN：发起一个连接。
    ◆FIN：释放一个连接。
●窗口大小字段：占16比特。此字段用来进行流量控制。单位为字节数，这个值是本机期望一次接收的字节数。
●TCP校验和字段：占16比特。对整个TCP报文段，即TCP头部和TCP数据进行校验和计算，并由目标端进行验证。
●紧急指针字段：占16比特。它是一个偏移量，和序号字段中的值相加表示紧急数据最后一个字节的序号。
●选项字段：占32比特。可能包括"窗口扩大因子"、"时间戳"等选项。

选项字段： 目前定义在rfc793 中有三个kind。详细描述的可查看 https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml

    Currently defined options include (kind indicated in octal):

      Kind     Length    Meaning
      ----     ------    -------
       0         -       End of option list.
       1         -       No-Operation.
       2         4       Maximum Segment Size.

 */
type TCPHeader struct {
	SrcPort 	uint16
	DstPort		uint16
	SeqNum		uint32
	AckNum		uint32
	Offset		uint8
	Flag 		uint8
	Window		uint16
	CheckSum	uint16
	UrgentPtr	uint16
}

/**
	TCP伪首部
 */
type PsdHeader struct {
	SrcAddr 	uint32
	DstAddr		uint32
	Zero		uint8
	ProtoType	uint8
	TcpLength	uint16
}

func inet_addr(ipaddr string) uint32 {
	var(
		segments []string = strings.Split(ipaddr,".")
		ip [4]uint64
		ret uint64
	)

	for i :=0; i<4;i++{
		ip[i],_ = strconv.ParseUint(segments[i],10,64)
	}
	ret = ip[3]<<24+ip[2]<<16+ip[1]<<8+ip[0]
	return uint32(ret)
}

func htons(port uint16) uint16 {
	var (
		high uint16 = port>>8
		ret uint16 = port<<8 + high
	)
	return ret
}

/**
检验和计算过程

        TCP首部校验和计算三部分：TCP首部+TCP数据+TCP伪首部。
发送端：
        首先，把伪首部、TCP报头、TCP数据分为16位的字，如果总长度为奇数个字节，则在最后增添一个位都为0的字节。
        把TCP报头中的校验和字段置为0。
        其次，用反码相加法（对每16bit进行二进制反码求和）累加所有的16位字（进位也要累加，进位则将高位叠加到低位）。
        最后，将上述结果作为TCP的校验和，存在检验和字段中。

接收端：

        将所有原码相加，高位叠加到低位， 如计算结果的16位中每一位都为1，则正确，否则说明发生错误。  

 
验证示例：
          校验和  反码求和过程
        以4bit 为例
        发送端计算：
        数据：   1000  0100   校验和  0000
        则反码：0111  1011               1111
        叠加：   0111+1011+1111 = 0010 0001   高于4bit的， 叠加到低4位      0001 + 0010 = 0011 即为校验和
 
        接收端计算：
        数据：  1000   0100   检验和  0011
        反码：  0111   1011                1100
        叠加：  0111 + 1011 +1100 = 0001 1110  叠加为4bit为1111.   全为1，则正确
 */
func CheckSum(data []byte)uint16  {
	var(
		sum uint32
		length int = len(data)
		index int
	)

	for length >1{
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}

	if length >0{
		sum += uint32(data[index])
	}

	sum += (sum >> 16)

	return uint16(^sum)
}
