/*
In CBC (Cipher Block Chaining) mode of operation, padding is required when the plaintext size is not a multiple of the block size.
Padding can be done in various ways, but the most secure way of padding in CBC is using the PKCS#7 padding scheme.

PKCS#7 padding adds bytes to the plaintext to make it a multiple of the block size, where the value of each byte added is equal to the number of bytes added.
For example, if two bytes are added to the plaintext, each byte will have the value 0x02. If eight bytes are added, each byte will have the value 0x08.
This makes it easy to remove the padding after decryption, as the value of the padding bytes can be used to determine how many bytes to remove.

One important thing to keep in mind is that the padding must always be applied, even if the plaintext is already a multiple of the block size.
This is to ensure that the encryption process is deterministic and that an attacker cannot distinguish between padded and unpadded messages.
*/

void PKCS_7(unsigned char* message, int message_length, int block_size, int padded_length, unsigned char* padded_message)
{
    // Calculate the number of padding bytes needed
    int padding_length = block_size - (message_length % block_size);

    // Set the padding byte values
    unsigned char pad_byte = padding_length;

    // Fill the padded message with the original message plus padding bytes
    for (int i = 0; i < message_length + padding_length; i++) {
        if (i < message_length)
            padded_message[i] = message[i];
        else
            padded_message[i] = pad_byte;
    }
}