/*  NetBare - An android network capture and injection library.
 *  Copyright (C) 2018-2019 Megatron King
 *  Copyright (C) 2018-2019 GuoShi
 *
 *  NetBare is free software: you can redistribute it and/or modify it under the terms
 *  of the GNU General Public License as published by the Free Software Found-
 *  ation, either version 3 of the License, or (at your option) any later version.
 *
 *  NetBare is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 *  without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 *  PURPOSE. See the GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along with NetBare.
 *  If not, see <http://www.gnu.org/licenses/>.
 */
package com.github.megatronking.netbare.ip.header;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;

/**
 * A summary of the contents of the internet header follows:
 *
 * 0                   1                   2                   3
 * 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |Version|  IHL  |Type of Service|          Total Length         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |         Identification        |Flags|      Fragment Offset    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |  Time to Live |    Protocol   |         Header Checksum       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Source Address                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Destination Address                        |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                    Options                    |    Padding    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * See https://tools.ietf.org/html/rfc791#section-3.1
 *
 * @author Megatron King
 * @since 2018-10-10 21:02
 */
public final class IpHeader extends Header {

    public static final int MIN_HEADER_LENGTH = 20;

    private static final int OFFSET_PROTOCOL = 9;
    private static final int OFFSET_VER_IHL = 0;
    private static final int OFFSET_SRC_IP = 12;
    private static final int OFFSET_DEST_IP = 16;
    private static final int OFFSET_TOTAL_LENGTH = 2;
    private static final int OFFSET_CRC = 10;

    public IpHeader(ByteBuffer packet, int offset) {
    	super(packet, offset);
	}

    public byte getProtocol() {
    	return getBuffer().get(offset + OFFSET_PROTOCOL);
    }

    public void setProtocol(byte protocol) {
        getBuffer().put(offset + OFFSET_PROTOCOL, protocol);
    }

    public char getHeaderLength() {
        return (char)((getBuffer().get(offset + OFFSET_VER_IHL) & 0x0F) << 2);
    }

    public void setHeaderLength(char length) {
		getBuffer().put(offset + OFFSET_VER_IHL, (byte) ((getBuffer().get(offset + OFFSET_VER_IHL) & 0xF0) | (length >> 2)));
    }

    public InetAddress getSourceIp(){
    	byte[] address = new byte[4];
    	getBuffer().position(offset + OFFSET_SRC_IP);
    	getBuffer().get(address);
    	try {
			return InetAddress.getByAddress(address);
		} catch (UnknownHostException e) {
    		e.printStackTrace();
		}
    	return null;
    }

    public void setSourceIp(InetAddress inetAddress) {
    	getBuffer().position(offset + OFFSET_SRC_IP);
    	getBuffer().put(inetAddress.getAddress());
    }

	public InetAddress getDestinationIp() {
		byte[] address = new byte[4];
		getBuffer().position(offset + OFFSET_DEST_IP);
		getBuffer().get(address);
		try {
			return InetAddress.getByAddress(address);
		} catch (UnknownHostException e) {
			e.printStackTrace();
		}
		return null;
	}

	public void setDestinationIp(InetAddress inetAddress) {
		getBuffer().position(offset + OFFSET_DEST_IP);
		getBuffer().put(inetAddress.getAddress());
	}

    public short getDataLength() {
        return (short)(this.getTotalLength() - this.getHeaderLength());
    }

    public short getTotalLength() {
        return getBuffer().getShort(offset + OFFSET_TOTAL_LENGTH);
    }

    public void setTotalLength(short length) {
    	getBuffer().putShort(offset + OFFSET_TOTAL_LENGTH, length);
    }

    public short getCrc() {
        return getBuffer().getShort(offset + OFFSET_CRC);
    }

    public void setCrc(short crc) {
        getBuffer().putShort(offset + OFFSET_CRC, crc);
    }

    public void updateChecksum() {
        setCrc((short) 0);
        setCrc(computeChecksum());
    }

    public long getIpSum() {
        // length 8 = src ip(4) + dest ip(4)
        return getSum(offset + OFFSET_SRC_IP, 8);
    }

    private short computeChecksum() {
        // The checksum field is the 16 bit one's complement of the one's complement sum of all
        // 16 bit words in the header.
        int len = getHeaderLength();
        long sum = getSum(offset, len);
        while ((sum >> 16) > 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (short) ~sum;
    }

}
