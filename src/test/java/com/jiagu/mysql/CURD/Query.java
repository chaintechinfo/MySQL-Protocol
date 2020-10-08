package com.jiagu.mysql.CURD;

import com.jiagu.mysql.protocol.AuthPacket;
import com.jiagu.mysql.protocol.Capabilities;
import com.jiagu.mysql.protocol.ColumnCountPacket;
import com.jiagu.mysql.protocol.ColumnDefinitionPacket;
import com.jiagu.mysql.protocol.CreateDBPacket;
import com.jiagu.mysql.protocol.EOFPacket;
import com.jiagu.mysql.protocol.ErrorPacket;
import com.jiagu.mysql.protocol.FieldListPacket;
import com.jiagu.mysql.protocol.HandshakePacket;
import com.jiagu.mysql.protocol.MysqlMessage;
import com.jiagu.mysql.protocol.MysqlPacket;
import com.jiagu.mysql.protocol.OKPacket;
import com.jiagu.mysql.protocol.QueryPacket;
import com.jiagu.mysql.protocol.QuitPacket;
import com.jiagu.mysql.protocol.ResultsetRowPacket;
import com.jiagu.mysql.protocol.util.ByteUtil;
import com.jiagu.mysql.protocol.util.HexUtil;
import com.jiagu.mysql.protocol.util.SecurityUtil;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

/**
 * Created by jintx on 2018/10/26.
 */
@Slf4j
public class Query {

    /**
     * 用来转化二进制到十六进制的
     */
    private final static byte[] hex = "0123456789ABCDEF".getBytes();

    /**
     * 客户端->服务端: 三次握手
     * 服务端发送 hand shake，客户端处理
     * 客户端发送 auth，服务端处理
     * 服务端返回 ok，客户端处理
     * 客户端发送 set names utf8 命令，服务端返回 ok
     * 客户端发送 set autocommit=0, 服务端返回 ok
     * 服务端发送查询命令，服务端返回 结果集
     */
    public void query(String host, int port, String user, String password, String dataBase, String sqlStr) throws Exception {
        OKPacket okPacket = null;
        Socket socket = new Socket();

        // 三次握手建立连接
        threeHands(socket, host, port);

        // 客户端解析 handshake packet, 得到在 CHAP 协议中使用的 seed (scramble 一个挑战随机数)
        InputStream inputStreams = socket.getInputStream();
        HandshakePacket handshakePacket = processHandShake(inputStreams);

        // 发送 Auth Packet：HandShakeResponse
        OutputStream outputStream = socket.getOutputStream();
        sendAuthPacket(handshakePacket, user, password, dataBase, outputStream);

        // 解析 OK packet 包
        okPacket = processOKPacket(inputStreams);
        if (okPacket.header != 0x00)
            throw new Exception("服务端对认证包验证后，返回的OK包中标志位不为0x00");

        // 发送 query set names utf8 的命令
        sendQueryPacket(outputStream, "SET NAMES utf8");
        // ErrorPacket errorPacket = processErrorPacket(inputStreams);
        processServerResponse(inputStreams);
//        okPacket = processOKPacket(inputStreams);
//        if (okPacket.header != 0x00)
//            throw new Exception("服务端对请求包执行后，返回的OK包中标志位不为0x00");

        // 发送 SET autocommit=0 的命令
        sendQueryPacket(outputStream, "SET autocommit=0");

        // 解析 OK packet 包
        okPacket = processOKPacket(inputStreams);
        if (okPacket.header != 0x00)
            throw new Exception("服务端对请求包执行后，返回的OK包中标志位不为0x00");

        // 发送 query packet包
        sendQueryPacket(outputStream, sqlStr);

        // 解析 result
        processResult(inputStreams);

        // 创建 db
        // sendCreateDbCommand(outputStream);
        // processServerResponse(inputStreams);

        sendQueryPacket(outputStream, "use employees");
        processOKPacket(inputStreams);
        getColumnDef(outputStream, "departments".getBytes());
        processGetColDef(inputStreams);

        // 解析完毕发送 Quit 包给服务端
        sendQuitPacket(socket, outputStream);
    }

    private void processGetColDef(InputStream inputStreams) throws Exception {
        byte[] bytesTemp = new byte[1024 * 16];//临时存放输入流的字节，一个数据最多含有2^24-1个字节

        int len = inputStreams.read(bytesTemp);
        byte[] bytes = new byte[len];
        System.arraycopy(bytesTemp, 0, bytes, 0, len);

        MysqlMessage mm = new MysqlMessage(bytes);
        mm.readUB3();
        mm.read();
        byte header = mm.read();

        if (header == ErrorPacket.header) {
            ErrorPacket errorPacket = new ErrorPacket();
            errorPacket.read(bytes);
            log.info("Got an error packet {}, message = {}", errorPacket, new String(errorPacket.message));
            throw new RuntimeException("Got an error packet");
        }
    }

    public void sendCreateDbCommand(OutputStream outputStream) throws Exception {
        // Create DB Packet
        CreateDBPacket createDBPacket = new CreateDBPacket();
        createDBPacket.packetId = 0;
        createDBPacket.flag = CreateDBPacket.COM_CREATE_DB;

        createDBPacket.schema = new byte[]{ 't', 'e', 's', 't', '1' };

        ByteBuffer byteBuffer = ByteBuffer.allocate(256);
        createDBPacket.write(byteBuffer);
        byteBuffer.flip();

        byte[] bytes = new byte[byteBuffer.remaining()];
        byteBuffer.get(bytes, 0, bytes.length);

        log.info("{}", HexUtil.Bytes2HexString(bytes));

        outputStream.write(bytes);
        outputStream.flush();
    }

    public void sendQuitPacket(Socket socket, OutputStream outputStream) throws Exception {
        byte[] quitPacket = produceQuit();
        outputStream.write(quitPacket);
        socket.shutdownOutput();
    }

    /**
     * 三次握手，打通socket
     *
     * @param socket
     * @param host   IP地址
     * @param port   端口号
     * @throws IOException
     */

    public void threeHands(Socket socket, String host, int port) throws IOException {
        socket.connect(new InetSocketAddress(host, port));
        log.info("Connect to {}:{}, and three hands succeed !", host, port);
    }

    /**
     * 解析握手包，生成对应的加密的密码，发送认证包
     *
     * @param handshakePacket 服务端发送的握手包
     * @param user            用户名
     * @param password        密码
     * @param dataBase        数据库名
     * @param outputStream    用来输出字节流
     * @throws Exception
     */
    public void sendAuthPacket(HandshakePacket handshakePacket,
                               String user,
                               String password,
                               String dataBase,
                               OutputStream outputStream) throws Exception {
        // 发送authPacket包
        byte[] authPacket = produceAuthPacket(handshakePacket.seed, handshakePacket.restOfScrambleBuff, user, password, dataBase);
        outputStream.write(authPacket);
        outputStream.flush();
        log.info("Sending auth packet ({}:{}/{}) succeed !", user, password, dataBase);
    }

    public void processServerResponse(InputStream inputStreams) throws Exception {
        byte[] bytesTemp = new byte[1024 * 16];//临时存放输入流的字节，一个数据最多含有2^24-1个字节

        int len = inputStreams.read(bytesTemp);
        byte[] bytes = new byte[len];
        System.arraycopy(bytesTemp, 0, bytes, 0, len);

        MysqlMessage mm = new MysqlMessage(bytes);
        mm.readUB3();
        mm.read();
        byte header = mm.read();
        if (header == OKPacket.HEADER) {
            // ok packet
            OKPacket okPacket = new OKPacket();
            okPacket.read(bytes);

            if (okPacket.header != 0x00)
                throw new Exception("服务端对请求包执行后，返回的OK包中标志位不为0x00");
        } else {
            // error packet
            ErrorPacket errorPacket = new ErrorPacket();
            errorPacket.read(bytes);

            log.info("{}, error message = {}", errorPacket, new String(errorPacket.message));

            throw new RuntimeException("Got an error packet: " + errorPacket);
        }
    }

    /**
     * 返回OK包
     *
     * @param inputStreams 输入流
     * @return 返回OK Packet
     * @throws Exception
     */
    public OKPacket processOKPacket(InputStream inputStreams) throws Exception {
        byte[] bytesTemp = new byte[1024 * 16];//临时存放输入流的字节，一个数据最多含有2^24-1个字节

        int len = inputStreams.read(bytesTemp);
        byte[] bytes = new byte[len];
        System.arraycopy(bytesTemp, 0, bytes, 0, len);
        //System.out.println("OK 包的十六进制:"+Bytes2HexString(bytes));
        OKPacket okPacket = new OKPacket();
        okPacket.read(bytes);

        log.info("OK Packet {}, header = {}, affectedRows = {}, serverStatus = {}, message = {}",
                okPacket, okPacket.header, okPacket.affectedRows, okPacket.serverStatus,
                okPacket.message == null ? "null" : new String(okPacket.message));

        // OKPacket okPacket1 = new OKPacket();
        // okPacket1.read(OKPacket.OK);
        // log.info("OK: {}", okPacket1);
        return okPacket;
    }

    public ErrorPacket processErrorPacket(InputStream inputStreams) throws Exception {

        byte[] bytesTemp = new byte[1024 * 16];
        int len = inputStreams.read(bytesTemp);
        byte[] bytes = new byte[len];
        System.arraycopy(bytesTemp, 0, bytes, 0, len);

        ErrorPacket errorPacket = new ErrorPacket();
        errorPacket.read(bytes);
        return errorPacket;
    }

    /**
     * 返回columnCountPacket
     *
     * @param bytes 字节数组
     * @return
     */
    public ColumnCountPacket processColumnCountPacket(byte[] bytes) {
        ColumnCountPacket columnCountPacket = new ColumnCountPacket();
        columnCountPacket.read(bytes);
        ByteUtil.bytesCut(columnCountPacket, bytes);
        return columnCountPacket;
    }

    /**
     * 返回一个EOF包
     *
     * @param bytes 字节数组
     * @return
     */
    public EOFPacket processEOFPacket(byte[] bytes) {
        EOFPacket eofPacket = new EOFPacket();
        eofPacket.read(bytes);
        //System.arraycopy(bytes, eofPacket.packetLength+4, bytes, 0, bytes.length- eofPacket.packetLength-4);
        ByteUtil.bytesCut(eofPacket, bytes);
        //System.out.println("截取掉eof之后的十六进制："+Bytes2HexString(bytes));
        return eofPacket;
    }

    /**
     * 将服务端返回的字节数组解析成columnCount、columnDef、Eof、resultSet等
     *
     * @param inputStreams 输入流
     * @throws Exception
     */
    public void processResult(InputStream inputStreams) throws Exception {
        byte[] bytesTemp = new byte[1024 * 16];
        int len = inputStreams.read(bytesTemp);
        byte[] bytes = new byte[len];
        System.arraycopy(bytesTemp, 0, bytes, 0, len);

        // 解析 columnCountPacket
        ColumnCountPacket columnCountPacket = processColumnCountPacket(bytes);
        log.info("{}, columnCount = {}", columnCountPacket, columnCountPacket.columnCount);

        // 解析 columnDef 包
        StringBuilder colName = new StringBuilder();
        ColumnDefinitionPacket[] columnDefinitionPackets = parseColumnDefinition(columnCountPacket.columnCount, bytes);
        for (ColumnDefinitionPacket columnDefinitionPacket : columnDefinitionPackets) {
            log.info("{}, table = {}, orgName = {}, name = {}",
                    columnDefinitionPacket,
                    new String(columnDefinitionPacket.table),
                    new String(columnDefinitionPacket.orgName),
                    new String(columnDefinitionPacket.name));

            colName.append(new String(columnDefinitionPacket.name, "utf-8"));
            colName.append(", ");
        }

        // 获取 EOF 包
        EOFPacket eofPacket = processEOFPacket(bytes);
        log.info("{}, warningCount = {}", eofPacket, eofPacket.warningCount);

        // 解析 resultSetRow 包
        ArrayList<ResultsetRowPacket> resultSetRowPackets = getResultSetRows(columnCountPacket.columnCount, bytes);

        log.info("====== ResultSet ======");
        log.info("{}", colName.toString());
        for (ResultsetRowPacket r : resultSetRowPackets) {
            StringBuilder row = new StringBuilder();
            for (int i = 0; i < columnCountPacket.columnCount; i++) {
                row.append(new String(r.columnValues.get(i), "utf-8"));
                row.append(", ");
            }

            log.info("{}", row.toString());
        }
    }


    /**
     * 读入服务端返回的字节数组，写入到握手包中
     *
     * @param inputStream 用来接受字节流
     * @return 返回一个握手包
     * @throws Exception
     */
    public HandshakePacket processHandShake(InputStream inputStream) throws Exception {
        // 临时存放输入流的字节，一个数据最多含有2^24-1个字节
        byte[] bytesTemp = new byte[1024 * 1024 * 16];
        int len = 0;

        // 接受 handshake 包
        len = inputStream.read(bytesTemp);
        byte[] bytes = new byte[len];
        System.arraycopy(bytesTemp, 0, bytes, 0, len);
        //System.out.println("handshake包的十六进制:"+Bytes2HexString(bytes));

        //解析handshake包
        HandshakePacket handshakePacket = new HandshakePacket();
        handshakePacket.read(bytes);

        log.info("{}, protocol version = {}, server version = {}, connection id = {}, capabilities = {}, seed = {}, seed length = {}", handshakePacket,
                handshakePacket.protocolVersion,
                new String(handshakePacket.serverVersion),
                handshakePacket.threadId,
                handshakePacket.serverCapabilities,
                new String(handshakePacket.seed), handshakePacket.seed.length
        );
        return handshakePacket;
    }

    /**
     * 解析resultSetRow 包
     *
     * @param columnCount 列的数值
     * @param bytes       返回的字节数组
     * @return 把结果分装在resultSetRow数组中
     */
    public ArrayList<ResultsetRowPacket> getResultSetRows(int columnCount, byte[] bytes) {
        EOFPacket eofPacket = new EOFPacket();
        ArrayList<ResultsetRowPacket> result = new ArrayList<ResultsetRowPacket>();
        while (true) {
            // 读到了一个 EOF 包，表示结束
            eofPacket.read(bytes);
            if ((eofPacket.header & 0xff) == 0xfe)
                break;

            ResultsetRowPacket resultSetRowPacket = new ResultsetRowPacket(columnCount);
            resultSetRowPacket.read(bytes);
            System.arraycopy(bytes, resultSetRowPacket.packetLength + 4, bytes, 0, bytes.length - resultSetRowPacket.packetLength - 4);
            result.add(resultSetRowPacket);
        }

        return result;
    }

    /**
     * 发送请求包.
     *
     * @param outputStream 输出流
     * @param queryStr     查询命令
     * @throws Exception
     */
    public void sendQueryPacket(OutputStream outputStream, String queryStr) throws Exception {
        byte[] queryPacket = produceQueryPacket(queryStr);
        outputStream.write(queryPacket);
        outputStream.flush();
    }

    /**
     * 获取ColumnDef,根据columnCountPacket中的columnCount将结果分装在ColumnDef中
     *
     * @param columnCount columnCountPacket中的filed数
     * @param bytes       服务端传回的字节数组
     * @return 返回columnDef的数组
     */
    public ColumnDefinitionPacket[] parseColumnDefinition(int columnCount, byte[] bytes) {
        ColumnDefinitionPacket[] result = new ColumnDefinitionPacket[columnCount];
        for (int i = 0; i < columnCount; i++) {
            ColumnDefinitionPacket columnDefPacket = new ColumnDefinitionPacket();
            columnDefPacket.read(bytes);
            result[i] = columnDefPacket;
            int deleteCount = columnDefPacket.packetLength + 4;
            ByteUtil.bytesCut(columnDefPacket, bytes);
            //System.arraycopy(bytes, deleteCount, bytes, 0, bytes.length-deleteCount);
            //System.out.println("解析了columnDef之后的值"+Bytes2HexString(bytes));
        }
        return result;
    }

    /**
     * 根据handshake包中的salt1和salt2生成加密的密码，将用户名、密码、数据库名一起打包成authPacket发送给服务端
     *
     * @param rand1    salt1长度为8
     * @param rand2    salt2长度为12
     * @param user     用户名
     * @param password 未加密的密码
     * @param database 要操作的数据库名
     * @return 返回auth packet的二进制
     */
    public byte[] produceAuthPacket(byte[] rand1, byte[] rand2, String user, String password, String database) {

        byte[] seed = new byte[rand1.length + rand2.length];
        System.arraycopy(rand1, 0, seed, 0, rand1.length);
        System.arraycopy(rand2, 0, seed, rand1.length, rand2.length);

        AuthPacket auth = new AuthPacket();
        auth.packetId = 1;
        auth.clientFlags = getClientCapabilities();
        auth.maxPacketSize = 1024 * 1024 * 1024;
        auth.user = user;
        try {
            auth.password = SecurityUtil
                    .scramble411(password.getBytes(), seed);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        auth.database = database;

        ByteBuffer buffer = ByteBuffer.allocate(256);
        auth.write(buffer);
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes, 0, bytes.length);
        return bytes;
    }

    /**
     * 将查询语句打包成query packet，发送给服务端查询
     *
     * @param queryStr 查询语句
     * @return 查询语句的二进制包
     */
    public byte[] produceQueryPacket(String queryStr) {
        QueryPacket query = new QueryPacket();
        query.flag = 3;//查询的标记，3为query
        query.message = queryStr.getBytes();
        // query.packetId = 2;

        log.info("Query packet: {}, packetId = {}, message = {}", query, query.packetId, new String(query.message));

        ByteBuffer buffer = ByteBuffer.allocate(256);
        query.write(buffer);//将包的大小、packedId(包的序列号)，flag,message，写到Buffer中
        buffer.flip();//写模式转为读模式
        byte[] bytes = new byte[buffer.remaining()];//buffer.remaining表示buffer中可读的为多少
        buffer.get(bytes, 0, bytes.length);//最后将请求的参数的二进制放在了bytes里
        return bytes;
    }

    /**
     * 产生一个Quit包
     *
     * @return Quit的字节数组
     */
    public byte[] produceQuit() {
        QuitPacket quit = new QuitPacket();
        quit.payload = 1;
        quit.packetId = 0;
        ByteBuffer buffer = ByteBuffer.allocate(256);
        quit.write(buffer);
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes, 0, bytes.length);
        return bytes;
    }

    public void getColumnDef(OutputStream outputStream, byte[] table) throws Exception {
        // byte[] table = { 't', 'e', 's', 't' };
        byte[] fieldWildcard = { 'w', 'h', 'e', 'r', 'e' };

        FieldListPacket fieldListPacket = new FieldListPacket();
        fieldListPacket.packetId = 0;
        fieldListPacket.table = table;
        fieldListPacket.fieldWildcard = fieldWildcard;
        fieldListPacket.flag = MysqlPacket.COM_FIELD_LIST;
        ByteBuffer buffer = ByteBuffer.allocate(256);
        fieldListPacket.write(buffer);
        buffer.flip();
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes, 0, bytes.length);

        outputStream.write(bytes);
        outputStream.flush();
    }

    /**
     * 发送auth packet的时候，客户端的能力
     *
     * @return 返回一个标志，表示客户端可行功能
     */
    public int getClientCapabilities() {
        int flag = 0;
        flag |= Capabilities.CLIENT_LONG_PASSWORD;
        flag |= Capabilities.CLIENT_FOUND_ROWS;
        flag |= Capabilities.CLIENT_LONG_FLAG;
        flag |= Capabilities.CLIENT_CONNECT_WITH_DB;
        flag |= Capabilities.CLIENT_ODBC;
        flag |= Capabilities.CLIENT_IGNORE_SPACE;
        flag |= Capabilities.CLIENT_PROTOCOL_41;
        flag |= Capabilities.CLIENT_INTERACTIVE;
        flag |= Capabilities.CLIENT_IGNORE_SIGPIPE;
        flag |= Capabilities.CLIENT_TRANSACTIONS;
        flag |= Capabilities.CLIENT_SECURE_CONNECTION;
        return flag;
    }

    /**
     * 将二进制转为十六进制
     *
     * @param b 二进制
     * @return 返回十六进制
     */
    public String Bytes2HexString(byte[] b) {
        byte[] buff = new byte[2 * b.length];
        for (int i = 0; i < b.length; i++) {
            buff[2 * i] = hex[(b[i] >> 4) & 0x0f];
            buff[2 * i + 1] = hex[b[i] & 0x0f];
        }
        return new String(buff);
    }
}
