#include <arpa/inet.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * Websocket framing protocol
 * https://datatracker.ietf.org/doc/html/rfc6455#section-5.2
 *
 *  0                   1                   2                   3
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-------+-+-------------+-------------------------------+
 * |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
 * |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
 * |N|V|V|V|       |S|             |   (if payload len==126/127)   |
 * | |1|2|3|       |K|             |                               |
 * +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
 * |     Extended payload length continued, if payload len == 127  |
 * + - - - - - - - - - - - - - - - +-------------------------------+
 * |                               |Masking-key, if MASK set to 1  |
 * +-------------------------------+-------------------------------+
 * | Masking-key (continued)       |          Payload Data         |
 * +-------------------------------- - - - - - - - - - - - - - - - +
 * :                     Payload Data continued ...                :
 * + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
 * |                     Payload Data continued ...                |
 * +---------------------------------------------------------------+
 */

#define FIN_BIT 0x80
#define MASK_BIT 0x80

#define OPCODE_CONTINUE 0x0
#define OPCODE_TEXT 0x1
#define OPCODE_BINARY 0x2
#define OPCODE_CLOSE 0x8
#define OPCODE_PING 0x9
#define OPCODE_PONG 0xA

#define PAYLOAD_MASK 0x7F
#define OPCODE_MASK 0x0F

#define MASK_OFFSET_DEFAULT 2
#define EXTENDED_LENGTH_IDENTIFIER 126
#define MASKING_KEY_LENGTH 4

#define MAX_FRAME_BUFFER_LENGTH 1024

#define WS_SHA_GUID_KEY "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

/**
 * Encode data into a Base64-encoded string.
 *
 * @param input Pointer to the input data to be encoded.
 * @param length Length of the input data.
 *
 * @returns
 * A dynamically allocated C string containing the Base64-encoded result.
 * The caller is responsible for freeing the returned string.
 * */
char *base_64_encode(const unsigned char *input, int length)
{
    // Create a new BIO (Basic Input/Output) memory buffer
    BIO *bio_mem = BIO_new(BIO_s_mem());
    // Create a new BIO for Base64 encoding
    BIO *bio_64 = BIO_new(BIO_f_base64());
    // Chain the Base64 BIO onto the memory BIO
    bio_64 = BIO_push(bio_64, bio_mem);

    // Write the input data to the Base64 BIO
    BIO_write(bio_64, input, length);
    // Ensure all data is written out
    BIO_flush(bio_64);

    // Get a pointer to the memory buffer managed by 'bio_mem'
    BUF_MEM *bio_ptr;
    BIO_get_mem_ptr(bio_64, &bio_ptr);

    // Allocate memory for the encoded string, plus one extra byte for a null terminator
    // This is necessary because 'input' may not be a valid C string; it could contain raw binary
    // data
    char *encoded = (char *)malloc(bio_ptr->length);
    // Copy the Base64-encoded data into the buffer, excluding the null terminator from the original
    // data
    memcpy(encoded, bio_ptr->data, bio_ptr->length - 1);
    // Manually add the null terminator to ensure the buffer is a valid C string
    encoded[bio_ptr->length - 1] = '\0';

    // Free BIO chain from bio_64
    BIO_free_all(bio_64);

    return encoded;
}

/**
 * Compute the SHA-1 hash of a given input string.
 *
 * @param input Pointer to the input string to be hashed.
 *
 * @returns
 * A dynamically allocated buffer containing the SHA-1 hash.
 * The caller is responsible for freeing the returned buffer.
 */
char *sha1(const char *input)
{
    // Array to hold the resulting SHA-1 hash (20 bytes)
    unsigned char hash[SHA_DIGEST_LENGTH];

    // Compute the SHA-1 hash of the input string
    SHA1((unsigned char *)input, strlen(input), hash);

    // Allocate memory for the output buffer to hold the hash, then copy
    char *output = (char *)malloc(SHA_DIGEST_LENGTH);
    memcpy(output, hash, SHA_DIGEST_LENGTH);

    return output;
}

/**
 * Send a WebSocket frame to a specified client.
 *
 * @param client_fd File descriptor for the client socket.
 * @param message Pointer to the message to be sent.
 */
void send_frame(int client_fd, const char *message)
{
    // Determine the length of the message to be sent
    size_t message_len = strlen(message);

    // Allocate a frame buffer with the necessary size (2 bytes for headers + message length)
    unsigned char frame[2 + message_len];

    // Set the first byte of the frame to indicate the final frame and text payload (0x81)
    frame[0] = FIN_BIT | OPCODE_TEXT;
    // Set the second byte to the length of the message
    frame[1] = message_len;

    // Copy the message into the frame, starting after the headers
    memcpy(&frame[2], message, message_len);

    // Send the constructed frame to the client using the provided file descriptor
    send(client_fd, frame, sizeof(frame), 0);
}

/**
 * Receive a WebSocket frame from a specified client.
 *
 * @param client_fd File descriptor for the client socket.
 *
 * @returns
 * A dynamically allocated buffer containing the unmasked payload from the WebSocket frame,
 * or NULL if an error occurs or the connection is closed. The caller is responsible for
 * freeing the returned buffer.
 */
char *receive_frame(int client_fd)
{
    // Buffer to hold the received data
    unsigned char buffer[MAX_FRAME_BUFFER_LENGTH];

    // Read data from the client socket into the buffer
    int bytes_read = recv(client_fd, buffer, sizeof(buffer), 0);

    // If no bytes are read or an error occurs, return NULL
    if (bytes_read <= 0) {
        return NULL;
    }

    // Extract the opcode from the first byte of the frame
    unsigned char opcode = buffer[0] & OPCODE_MASK;

    // Check if the client requested to close the connection
    if (opcode == OPCODE_CLOSE) {
        printf("Client requested to close the connection.\n");
        return NULL;
    }

    // Determine if the payload is masked and extract the payload length
    unsigned char mask = buffer[1] & MASK_BIT;
    unsigned char payload_len = buffer[1] & PAYLOAD_MASK;

    // Calculate the offset for the masking key and payload based on the payload length
    int mask_offset = MASK_OFFSET_DEFAULT;
    // Check for extended payload length (2 bytes)
    if (payload_len == EXTENDED_LENGTH_IDENTIFIER) {
        // Read the extended payload length
        payload_len = ntohs(*(uint16_t *)&buffer[MASK_OFFSET_DEFAULT]);
        // Adjust offset to account for the 2-byte length field
        mask_offset += 2;
    }

    // Array to hold the masking key if the payload is masked
    unsigned char masking_key[MASKING_KEY_LENGTH];
    // If the mask bit is set, retrieve the masking key
    if (mask) {
        // Copy the masking key from the buffer
        memcpy(masking_key, &buffer[mask_offset], MASKING_KEY_LENGTH);
        // Adjust offset to point to the payload data
        mask_offset += MASKING_KEY_LENGTH;
    }

    // Allocate memory for the payload, plus one byte for the null terminator
    char *payload = (char *)malloc(payload_len + 1);
    // Copy the payload data from the buffer into the allocated memory
    memcpy(payload, &buffer[mask_offset], payload_len);
    // Terminate the payload string
    payload[payload_len] = '\0';

    // If the payload is masked, unmask the data using the masking key
    if (mask) {
        for (int i = 0; i < payload_len; ++i) {
            // XOR each byte with the masking key
            payload[i] ^= masking_key[i % MASKING_KEY_LENGTH];
        }
    }

    return payload;
}

int main()
{
    // Create a socket for the server using IPv4 and TCP
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);

    // Set up the address structure for the server
    struct sockaddr_in address;
    // Use IPv4 address family
    address.sin_family = AF_INET;
    // Bind to all available interfaces
    address.sin_addr.s_addr = INADDR_ANY;
    // Set the port number (8080), converting to network byte order
    address.sin_port = htons(8080);

    // Bind the socket to the specified address and port
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    // Listen for incoming connections, with a backlog of 3
    listen(server_fd, 3);

    printf("Waiting for a connection...\n");

    // Accept a new connection from a client
    int client_fd = accept(server_fd, NULL, NULL);

    // Buffer to receive the client's HTTP request
    char buffer[MAX_FRAME_BUFFER_LENGTH] = {0};
    // Read the incoming request from the client
    recv(client_fd, buffer, sizeof(buffer), 0);

    // Extract the Sec-WebSocket-Key from the request headers
    char *key_start = strstr(buffer, "Sec-WebSocket-Key: ");
    char key[25];
    if (key_start) {
        // Move pointer to the start of the key value
        key_start += 19;
        // Copy up to 24 characters of the key
        strncpy(key, key_start, 24);
        // Terminate the key string
        key[24] = '\0';
    }

    // Prepare the concatenation of the WebSocket key and the GUID for hashing
    char concat[61];
    snprintf(concat, sizeof(concat), "%s%s", key, WS_SHA_GUID_KEY);

    // Compute the SHA-1 hash of the concatenated string
    char *sha1_hash = sha1(concat);
    // Encode the SHA-1 hash in Base64 format to create the Sec-WebSocket-Accept value
    char *accept_key = base_64_encode((unsigned char *)sha1_hash, SHA_DIGEST_LENGTH);

    // Prepare the HTTP response for the WebSocket handshake
    char response[256];
    snprintf(response, sizeof(response),
             "HTTP/1.1 101 Switching Protocols\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Accept: %s\r\n\r\n",
             accept_key);
    // Send the handshake response to the client
    send(client_fd, response, strlen(response), 0);
    printf("Handshake response sent.\n");

    // Free allocated memory for the SHA-1 hash and Base64 encoded key
    free(sha1_hash);
    free(accept_key);

    // Main loop to handle incoming messages from the client
    while (1) {
        // Receive a WebSocket frame from the client
        char *message = receive_frame(client_fd);
        // Exit loop if no message is received (client disconnected)
        if (message == NULL) {
            break;
        }

        printf("Received: %s\n", message);

        send_frame(client_fd, "Hello from server");
        // Free the memory allocated for the received message
        free(message);
    }

    // Close the client and server sockets
    close(client_fd);
    close(server_fd);
    return 0;
}
