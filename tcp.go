package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

/**
这是从RFC791 拉下来的IP header

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |Version|  IHL  |Type of Service|          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Identification        |Flags|      Fragment Offset    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Time to Live |    Protocol   |         Header Checksum       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source Address                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination Address                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Options                    |    Padding    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                    Example Internet Datagram Header

●Version（版本）：占4比特，用来表明IP协议实现的版本号，当前一般为IPv4，即0100。

●IHL（报头长度）：占4比特，表示头部占32比特的长度是多少，比如说不包含任何选项的IP数据报，从上图可以看出到 Destination Address为止， 32x5=160比特=20字节，此字段最大值为60字节。

●Type of Service（服务类型）：占8个比特，其中前3比特为优先权子字段（Precedence，现已被忽略）。第8比特保留未用。第4至第7比特分别代表延迟、吞吐量、可靠性和花费。当它们取值为1时分别代表要求最小时延、最大吞吐量、最高可靠性和最小费用。这4比特的服务类型中只能置其中1比特为1。可以全为0，若全为0则表示一般服务。服务类型字段声明了数据报被网络系统传输时可以被怎样处理。

      Bits 0-2:  Precedence.
      Bit    3:  0 = Normal Delay,      1 = Low Delay.
      Bits   4:  0 = Normal Throughput, 1 = High Throughput.
      Bits   5:  0 = Normal Relibility, 1 = High Relibility.
      Bit    6:  0 = Normal Cost, 1 = High cost.
      Bit    7:  Reserved for Future Use.

         0     1     2     3     4     5     6     7
      +-----+-----+-----+-----+-----+-----+-----+-----+
      |                 |     |     |     |     |     |
      |   PRECEDENCE    |  D  |  T  |  R  |  0  |  0  |
      |                 |     |     |     |     |     |
      +-----+-----+-----+-----+-----+-----+-----+-----+

●Total Length（总长度字段）：占16比特。指明整个数据报的长度（以字节为单位）。最大长度为65535字节。
●Identification（标识）：占16比特。用来唯一地标识主机发送的每一份数据报。通常每发一份报文，它的值会加1。
●Flags（标志位）：占3比特，表示这份报文是否需要分片传输。
●TTL（生存期）：占8比特，用来表示该数据报文最多可以经过的路由器数，没经过一个路由器都减1，直到为0数据包丢掉。
●Protocal(协议字段)：占8比特，用来指出IP层所封装的上层协议类型，如传输层TCP/UDP/ICMP/IGMP。
●Header checksum(头部校验和字段)：占16比特，内容是根据IP头部计算得到的校验和码。计算方法是：对头部中每个16比特进行二进制反码求和。（和ICMP、IGMP、TCP、UDP不同，IP不对头部后的数据进行校验）。
●source address&&Dest address:源地址和目的地址，各占32字节，当然这个是针对的IPV4
●Option:占32比特。用来定义一些任选项：如记录路径、时间戳等。这些选项很少被使用，同时并不是所有主机和路由器都支持这些选项。可选项字段的长度必须是32比特的整数倍，如果不足，必须填充0以达到此长度要求。
 */






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

func main() {
	var(
		msg string = "test"
		psdHeader PsdHeader
		tcpHeader TCPHeader
	)

	//填充tcp伪首部
	psdHeader.SrcAddr = inet_addr("127.0.0.1")
	psdHeader.DstAddr = inet_addr("127.0.0.1")
	psdHeader.Zero = 0
	psdHeader.ProtoType = syscall.IPPROTO_TCP
	psdHeader.TcpLength = uint16(unsafe.Sizeof(TCPHeader{}))+uint16(len(msg))

	//填充tcp首部
	tcpHeader.SrcPort = htons(3000)
	tcpHeader.DstPort = htons(8080)
	tcpHeader.SeqNum = 0
	tcpHeader.AckNum = 0
	tcpHeader.Offset = uint8(uint16(unsafe.Sizeof(TCPHeader{}))/4)<<4
	tcpHeader.Flag = 2	//SYN
	tcpHeader.Window = 60000
	tcpHeader.CheckSum = 0

	/**buffer用来写入两种首部来求得校验和*/
	var (
		buffer bytes.Buffer
	)
	binary.Write(&buffer, binary.BigEndian, psdHeader)
	binary.Write(&buffer, binary.BigEndian, tcpHeader)
	tcpheader.Checksum = CheckSum(buffer.Bytes())

	/*接下来清空buffer，填充实际要发送的部分*/
	buffer.Reset()
	binary.Write(&buffer, binary.BigEndian, tcpHeader)
	binary.Write(&buffer, binary.BigEndian, msg)


	/*下面的操作都是raw socket操作，大家都看得懂*/
	var (
		sockfd int
		addr   syscall.SockaddrInet4
		err    error
	)
	if sockfd, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP); err != nil {
		log.Fatalf("Socket() error: %s", err.Error())
		return
	}
	defer syscall.Shutdown(sockfd, syscall.SHUT_RDWR)
	addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3] = 127, 0, 0, 1
	addr.Port = 8080
	if err = syscall.Sendto(sockfd, buffer.Bytes(), 0, &addr); err != nil {
		log.Fatalf("Sendto() error: %s", err.Error())
		return
	}



}
