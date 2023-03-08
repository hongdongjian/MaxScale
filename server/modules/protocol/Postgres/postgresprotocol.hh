/*
 * Copyright (c) 2023 MariaDB plc
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2027-02-21
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
#pragma once

#define MXB_MODULE_NAME "postgresprotocol"

#include <maxscale/ccdefs.hh>
#include <maxbase/assert.hh>
#include <maxscale/log.hh>
#include <maxscale/buffer.hh>
#include <maxscale/dcb.hh>

#include <endian.h>
#include <string_view>

namespace postgres
{
//
// Constants
//

// Length of the message header
//
// The header consists of a one byte command followed by network order 32-bit integer for the message length.
// The message length always includes the length itself so it'll always have a value of at least 4.
//
// Note that the first packet sent by a client does not have the command byte and is only 4 bytes long.
static constexpr size_t HEADER_LEN = 5;

// The protocol version for a normal StartupMessage for the v3 protocol.
// 3 in the most significant 16 bits (major version) and 0 in the least significant 16 bits (minor version).
static constexpr uint32_t PROTOCOL_V3_MAGIC = 196608;

// The protocol version for a SSLRequest message.
// 1234 in the most significant 16 bits and 5679 in the least significant 16 bits.
static constexpr uint32_t SSLREQ_MAGIC = 80877103;

// The protocol version for a CancelRequest message.
// 1234 in the most significant 16 bits and 5678 in the least significant 16 bits.
static constexpr uint32_t CANCEL_MAGIC = 80877102;

// The protocol version for a GSSENCRequest message.
// 1234 in the most significant 16 bits and 5680 in the least significant 16 bits.
static constexpr uint32_t GSSENC_MAGIC = 80877104;

// The one byte response sent for the SSLRequest message when SSL is enabled
static constexpr uint8_t SSLREQ_YES = 'S';

// The one byte response sent for the SSLRequest message when SSL is disable
static constexpr uint8_t SSLREQ_NO = 'N';

//
// Message types: https://www.postgresql.org/docs/current/protocol-message-formats.html
//

// Backend messages
enum BackendCommand : uint8_t
{
    // The Authentication message is a "message class" that covers multiple message types. The main type is
    // the AuthenticationOk message that signals the client that authentication was successful.
    AUTHENTICATION = 'R',

    BACKEND_KEY_DATA           = 'K',   // BackendKeyData
    BIND_COMPLETE              = '2',   // BindComplete
    CLOSE_COMPLETE             = '3',   // CloseComplete
    COMMAND_COMPLETE           = 'C',   // CommandComplete
    COPY_BOTH_RESPONSE         = 'W',   // CopyBothResponse, only for streaming replication
    COPY_IN_RESPONSE           = 'G',   // CopyInResponse
    COPY_OUT_RESPONSE          = 'H',   // CopyOutResponse
    DATA_ROW                   = 'D',   // DataRow
    EMPTY_QUERY_RESPONSE       = 'I',   // EmptyQueryResponse
    ERROR_RESPONSE             = 'E',   // ErrorResponse
    NEGOTIATE_PROTOCOL_VERSION = 'v',   // NegotiateProtocolVersion
    FUNCTION_CALL_RESPONSE     = 'V',   // FunctionCallResponse
    NO_DATA                    = 'n',   // NoData
    NOTICE_RESPONSE            = 'N',   // NoticeResponse
    NOTIFICATION_RESPONSE      = 'A',   // NotificationResponse
    PARAMETER_DESCRIPTION      = 't',   // ParameterDescription
    PARAMETER_STATUS           = 'S',   // ParameterStatus
    PARSE_COMPLETE             = '1',   // ParseComplete
    PORTAL_SUSPENDED           = 's',   // PortalSuspended
    READY_FOR_QUERY            = 'Z',   // ReadyForQuery
    ROW_DESCRIPTION            = 'T',   // RowDescription
};

// Client messages
enum ClientCommand : uint8_t
{
    BIND                  = 'B',// Bind
    CLOSE                 = 'C',// Close
    COPY_FAIL             = 'f',// CopyFail
    DESCRIBE              = 'D',// Describe
    EXECUTE               = 'E',// Execute
    FLUSH                 = 'F',// Flush
    GSS_RESPONSE          = 'p',// GSSResponse
    PARSE                 = 'P',// Parse
    PASSWORD_MESSAGE      = 'p',// PasswordMessage
    QUERY                 = 'Q',// Query
    SASL_INITIAL_RESPONSE = 'p',// SASLInitialResponse
    SASL_RESPONSE         = 'p',// SASLResponse
    SYNC                  = 'S',// Sync
    TERMINATE             = 'X',// Terminate
};

// Messages that are sent by both clients and backends
enum BidirectionalCommand : uint8_t
{
    COPY_DATA = 'd',    // CopyData
    COPY_DONE = 'c',    // CopyDone
};

// A connection can also send a StartupMessage as the first command. The command consists of:
//
//   Int32 -  The length of the message.
//   Int32 -  The protocol version.
//   String[]- The rest of the packet consists of null-terminated strings.
//
// In addition to a normal StartupMessage, the following special commands that look like
// a StartupMessage can be sent by the client:
//
// SSLRequest - StartupMessage with 80877103 as the version. Sent instead of the normal handshake if the
//              connection is encrypted.
//
// CancelRequest - StartupMessage with 80877102 as the version. This is a request to kill the connection.
//                 Instead of the string data, it contains two Int32 values that define the process ID and the
//                 secret key.
//
// GSSENCRequest - StartupMessage with 80877104 as the version. GSSAPI encryption request.

/**
 * Extract a 16-bit unsigned integer
 *
 * Postgres integers are stored in network order (big-endian).
 *
 * @param ptr Pointer to memory
 *
 * @return The value in host endianness
 */
static inline uint16_t get_uint16(const uint8_t* ptr)
{
    uint16_t value;
    memcpy(&value, ptr, sizeof(value));
    return be16toh(value);
}

/**
 * Extract a 32-bit unsigned integer
 *
 * Postgres integers are stored in network order (big-endian).
 *
 * @param ptr Pointer to memory
 *
 * @return The value in host endianness
 */
static inline uint32_t get_uint32(const uint8_t* ptr)
{
    uint32_t value;
    memcpy(&value, ptr, sizeof(value));
    return be32toh(value);
}

/**
 * Get a null-terminated string
 *
 * @warning The caller must ensure that the pointed to memory must contain a null-terminating character.
 *
 * @param ptr Pointer to memory
 *
 * @return The value as a std::string_view
 */
static inline std::string_view get_string(const uint8_t* ptr)
{
    const char* str = reinterpret_cast<const char*>(ptr);
    return std::string_view(str, strlen(str));
}

/**
 * Set a 16-bit unsigned integer
 *
 * @param ptr Pointer to memory
 * @param val Value to set
 *
 * @return sizeof(uint16_t)
 */
static inline size_t set_uint16(uint8_t* ptr, uint16_t val)
{
    uint16_t value = htobe16(val);
    memcpy(ptr, &value, sizeof(value));
    return sizeof(value);
}

/**
 * Set a 32-bit unsigned integer
 *
 * @param ptr Pointer to memory
 * @param val Value to set
 *
 * @return sizeof(uint32_t)
 */
static inline size_t set_uint32(uint8_t* ptr, uint32_t val)
{
    uint32_t value = htobe32(val);
    memcpy(ptr, &value, sizeof(value));
    return sizeof(value);
}

/**
 * Set a null-terminated string
 *
 * @param ptr Pointer to memory
 * @param str The string to set
 *
 * @return Length of the string plus one
 */
static inline size_t set_string(uint8_t* ptr, std::string_view str)
{
    memcpy(ptr, str.data(), str.size());
    ptr[str.size()] = 0x0;
    return str.size() + 1;
}

enum ExpectCmdByte
{
    YES,
    NO
};

/**
 * Reads a complete packet from the socket
 *
 * @param dcb DCB to read from
 *
 * @return True if the read was successful, false if an error occurred. If a complete packet was available,
 *         the buffer will contain it. If no complete packets are available an empty buffer is returned.
 */
std::tuple<bool, GWBUF> read_packet(DCB* dcb, ExpectCmdByte expect_cmd_byte = ExpectCmdByte::YES);

/**
 * Formats ErrorResponse or NoticeResponse messages into human-readable errors
 *
 * @param buffer Buffer that contains the message
 *
 * @return The formatted message
 */
std::string format_response(const GWBUF& buffer);
}

// Convenience alias for the namespace
namespace pg = postgres;