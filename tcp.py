#!/usr/bin/env python3


# Write a function that converts the dots-and-numbers IP addresses into bytestrings.
def ip_to_bytes(ip):
    # Split the IP at the dot
    octets = ip.split(".")
    # Octet -> byte and join bytes
    return bytes([int(octet) for octet in octets])


# Write a function that generates the IP pseudo header bytes from the IP addresses from tcp_addrs_0.txt and the TCP length from the tcp_data_0.dat file
def build_pseudo_header(src_bytes, dst_bytes, tcp_length):
    # Convert the length of the TCP data into bytes
    len_bytes = tcp_length.to_bytes(2, "big")
    # (4 bytes) + (4 bytes) + Z(1 byte) + P(1 byte) + TCP Length(2 bytes)
    return src_bytes + dst_bytes + b"\x00" + b"\x06" + len_bytes


# Compute the checksum
def checksum(pseudo_header, tcp_data):
    # Concatenate the pseudo header and the TCP data with zero checksum.
    data = pseudo_header + tcp_data

    total = 0
    offset = 0

    # Process every 16-bit word
    while offset < len(data) - 1:
        word = int.from_bytes(data[offset : offset + 2], byteorder="big")
        total += word
        # Carry around
        total = (total & 0xFFFF) + (total >> 16)
        offset += 2
    # Return one's complement
    return ~total & 0xFFFF


def run():
    print("Starting TCP Checker")
    # Read in the files starting with tcp_addrs_0.txt
    for n in range(10):
        # Read in the tcp_addrs_?.txt file.
        with open(f"tcp_addrs_{n}.txt") as tcp_addrs:
            # Split the line in two, the source and destination addresses.
            for line in tcp_addrs:
                src, dst = line.split()
                # print(f"Checking TCP from {src} to {dst}")
                # Convert the source and destination addresses to bytes.
                src_bytes = ip_to_bytes(src)
                dst_bytes = ip_to_bytes(dst)

                # Read in the tcp_data_0.dat file.
                with open(f"tcp_data_{n}.dat", "rb") as tcp_data:
                    tcp_data = tcp_data.read()
                    tcp_length = len(tcp_data)

                    # Build a new version of the TCP data that has the checksum set to zero.
                    tcp_zero_cksum = tcp_data[:16] + b"\x00\x00" + tcp_data[18:]

                    # Call my beautiful function
                    pseudo_header = build_pseudo_header(
                        src_bytes, dst_bytes, tcp_length
                    )

                    # Force it to be even length.
                    if len(tcp_zero_cksum) % 2 == 1:
                        tcp_zero_cksum += b"\x00"

                    # Compute the checksum over the new TCP data
                    computed_checksum = checksum(pseudo_header, tcp_zero_cksum)

                    # Extract the checksum from the original data in
                    real_checksum = int.from_bytes(tcp_data[16:18], byteorder="big")

                    # Compare the two checksums. If they’re identical, it works!
                    if computed_checksum == real_checksum:
                        print("true")
                    else:
                        print("false")


if __name__ == "__main__":
    run()
