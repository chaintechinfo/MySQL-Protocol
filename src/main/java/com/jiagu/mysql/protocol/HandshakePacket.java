package com.jiagu.mysql.protocol;

import java.nio.ByteBuffer;

import com.jiagu.mysql.protocol.util.BufferUtil;

/**
 * 
 * <pre><b>AuthPacket means mysql initial handshake packet.</b></pre>
 * @author 
 * <pre>seaboat</pre>
 * <pre><b>email: </b>849586227@qq.com</pre>
 * <pre><b>blog: </b>http://blog.csdn.net/wangyangzhizhou</pre>
 * @version 1.0
 * @see http://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::Handshake
 */
public class HandshakePacket extends MysqlPacket {
	private static final byte[] FILLER_13 = new byte[] { 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0 };

	// 协议版本号: 1 bytes
	public byte protocolVersion;
	// 可读的服务端版本号: StringNul, 以 00 结尾
	public byte[] serverVersion;
	// 连接id: 4 bytes
	public long threadId;

	// 挑战握手协议中，由服务端生成并发送来的 seed
	public byte[] seed;
	public int serverCapabilities;
	public byte serverCharsetIndex;
	public int serverStatus;

	// 这个其实就是 seed2，有两部分，第一部分是 seed
	public byte[] restOfScrambleBuff;

	@Override
	public void read(byte[] data) {
		MysqlMessage mm = new MysqlMessage(data);
		// 3 bytes 的 packet length
		packetLength = mm.readUB3();
		// 1 bytes 的 packet seq id
		packetId = mm.read();

		// 1 bytes 的 协议版本号
		protocolVersion = mm.read();
		// 读取版本号
		serverVersion = mm.readBytesWithNull();

		// 4 bytes connection id
		threadId = mm.readUB4();

		seed = mm.readBytesWithNull();

		serverCapabilities = mm.readUB2();
		serverCharsetIndex = mm.read();
		serverStatus = mm.readUB2();

		mm.move(13);
		restOfScrambleBuff = mm.readBytesWithNull();
	}

	@Override
	public int calcPacketSize() {
		int size = 1;
		size += serverVersion.length;
		size += 5;
		size += seed.length;
		size += 19;
		size += restOfScrambleBuff.length;
		size += 1;
		return size;
	}

	@Override
	public void write(ByteBuffer buffer) {
		BufferUtil.writeUB3(buffer, calcPacketSize());
		buffer.put(packetId);
		buffer.put(protocolVersion);
		BufferUtil.writeWithNull(buffer, serverVersion);
		BufferUtil.writeUB4(buffer, threadId);
		BufferUtil.writeWithNull(buffer, seed);
		BufferUtil.writeUB2(buffer, serverCapabilities);
		buffer.put(serverCharsetIndex);
		BufferUtil.writeUB2(buffer, serverStatus);
		buffer.put(FILLER_13);
		BufferUtil.writeWithNull(buffer, restOfScrambleBuff);
	}

	@Override
	protected String getPacketInfo() {
		return "MySQL Handshake Packet";
	}

}