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

#include "pgclientconnection.hh"
#include <maxscale/dcb.hh>
#include <maxscale/listener.hh>
#include <maxscale/service.hh>
#include "pgparser.hh"
#include "pgprotocoldata.hh"
#include "pgusermanager.hh"

using std::string;
using std::string_view;

namespace
{

void add_packet_auth_request(GWBUF& gwbuf, pg::Auth athentication_method)
{
    const size_t auth_len = 1 + 4 + 4;      // Byte1('R'), Int32(8) len, Int32 auth_method
    std::array<uint8_t, auth_len> data;

    uint8_t* ptr = begin(data);
    *ptr++ = pg::AUTHENTICATION;
    ptr += pg::set_uint32(ptr, 8);
    ptr += pg::set_uint32(ptr, athentication_method);

    gwbuf.append(begin(data), data.size());
}

void add_packet_ready_for_query(GWBUF& gwbuf)
{
    const size_t rdy_len = 1 + 4 + 1;       // Byte1('R'), Int32(8) len, Int8 trx status
    std::array<uint8_t, rdy_len> data;

    uint8_t* ptr = begin(data);
    *ptr++ = pg::READY_FOR_QUERY;
    ptr += pg::set_uint32(ptr, 5);
    *ptr++ = 'I';   // trx idle

    gwbuf.append(begin(data), data.size());
}
}

PgClientConnection::PgClientConnection(MXS_SESSION* pSession, mxs::Component* pComponent)
    : m_session(*pSession)
    , m_protocol_data(static_cast<PgProtocolData*>(pSession->protocol_data()))
    , m_ssl_required(m_session.listener_data()->m_ssl.config().enabled)
    , m_down(pComponent)
{
}

bool PgClientConnection::setup_ssl()
{
    auto state = m_dcb->ssl_state();
    mxb_assert(state != DCB::SSLState::ESTABLISHED);

    if (state == DCB::SSLState::HANDSHAKE_UNKNOWN)
    {
        m_dcb->set_ssl_state(DCB::SSLState::HANDSHAKE_REQUIRED);
    }

    return m_dcb->ssl_handshake() >= 0;
}

void PgClientConnection::ready_for_reading(DCB* dcb)
{
    mxb_assert(m_dcb == dcb);
    bool state_machine_continue = true;

    while (state_machine_continue)
    {
        switch (m_state)
        {
        case State::HANDSHAKE:
            state_machine_continue = state_handshake();
            break;

        case State::AUTH:
            state_machine_continue = state_auth();
            break;

        case State::ROUTE:
            state_machine_continue = state_route();
            break;

        case State::ERROR:
            m_session.kill();
            state_machine_continue = false;
            break;
        }
    }
}

bool PgClientConnection::state_handshake()
{
    bool caller_continue = true;
    bool state_machine_continue = true;

    auto handle_startup_message = [&](GWBUF&& buffer) {
        auto res = parse_startup_message(buffer);
        switch (res)
        {
        case StateMachineRes::IN_PROGRESS:
            m_dcb->unread(std::move(buffer));
            state_machine_continue = false;
            caller_continue = false;
            break;

        case StateMachineRes::DONE:
            state_machine_continue = false;
            m_state = State::AUTH;
            break;

        case StateMachineRes::ERROR:
            m_hs_state = HSState::FAIL;
            break;
        }
    };

    while (state_machine_continue)
    {
        switch (m_hs_state)
        {
        case HSState::INIT:
            {
                // Client may have sent a StartupMessage or an SSLRequest. Read a limited amount since client
                // cannot be trusted yet. Both packets are at least 8 bytes.
                auto [read_ok, buffer] = m_dcb->read(8, 100000);
                if (!buffer.empty())
                {
                    auto ptr = buffer.data();
                    uint32_t len = pg::get_uint32(ptr);
                    uint32_t code = pg::get_uint32(ptr + 4);

                    if (len == 8 && code == pg::SSLREQ_MAGIC)
                    {
                        if (buffer.length() == 8)
                        {
                            // Valid SSLRequest, reply with either 'S' or 'N'.
                            if (m_ssl_required)
                            {
                                uint8_t ssl_yes[] = {pg::SSLREQ_YES};
                                write(GWBUF {ssl_yes, sizeof(ssl_yes)});
                                if (setup_ssl())
                                {
                                    // SSL may not be done yet, but execution returns to this function only
                                    // after it's complete.
                                    m_hs_state = HSState::STARTUP_MSG;
                                    state_machine_continue = false;
                                    caller_continue = false;
                                }
                                else
                                {
                                    m_hs_state = HSState::FAIL;
                                }
                            }
                            else
                            {
                                uint8_t no_ssl[] = {pg::SSLREQ_NO};
                                write(GWBUF {no_ssl, sizeof(no_ssl)});
                                m_hs_state = HSState::STARTUP_MSG;
                                state_machine_continue = false;     // Message should not be available yet.
                                caller_continue = false;
                            }
                        }
                        else
                        {
                            // Invalid SSLRequest. Handle properly later.
                            m_hs_state = HSState::FAIL;
                        }
                    }
                    else
                    {
                        // Looks like client sent StartupMessage immediately.
                        if (m_ssl_required)
                        {
                            // Not allowed. TODO: add error message.
                            m_hs_state = HSState::FAIL;
                        }
                        else
                        {
                            handle_startup_message(std::move(buffer));
                        }
                    }
                }
                else if (read_ok)
                {
                    // Not enough data, wait for more.
                    state_machine_continue = false;
                    caller_continue = false;
                }
                else
                {
                    m_hs_state = HSState::FAIL;
                }
            }
            break;

        case HSState::STARTUP_MSG:
            {
                // Client should have sent a StartupMessage. It's at least (4 + 4 + 3) bytes.
                auto [read_ok, buffer] = m_dcb->read(11, 100000);
                if (!buffer.empty())
                {
                    handle_startup_message(std::move(buffer));
                }
                else if (read_ok)
                {
                    state_machine_continue = false;
                    caller_continue = false;
                }
                else
                {
                    m_hs_state = HSState::FAIL;
                }
            }
            break;

        case HSState::FAIL:
            state_machine_continue = false;
            m_state = State::ERROR;
            break;
        }
    }
    return caller_continue;
}

bool PgClientConnection::state_auth()
{
    bool caller_continue = true;
    bool state_machine_continue = true;

    while (state_machine_continue)
    {
        switch (m_auth_state)
        {
        case AuthState::FIND_ENTRY:
            if (check_user_account_entry())
            {
                m_auth_state = AuthState::COMPLETE;
            }
            else
            {
                m_auth_state = AuthState::FAIL;
            }
            break;

        case AuthState::COMPLETE:
            {
                // Send AuthenticationOk-message.
                GWBUF auth_ok(9);
                auto ptr = auth_ok.data();
                *ptr++ = 'R';
                ptr += pg::set_uint32(ptr, 8);
                pg::set_uint32(ptr, 0);
                write(std::move(auth_ok));

                state_machine_continue = false;
                m_state = prepare_session() ? State::ROUTE : State::ERROR;
            }
            break;

        case AuthState::FAIL:
            // TODO: send error
            m_state = State::ERROR;
            state_machine_continue = false;
            break;
        }
    }
    return caller_continue;
}

bool PgClientConnection::state_route()
{
    bool caller_continue = false;
    auto [ok, buffer] = pg::read_packet(m_dcb);
    if (!buffer.empty())
    {
        m_down->routeQuery(std::move(buffer));
    }
    else if (!ok)
    {
        m_state = State::ERROR;
        caller_continue = true;
    }
    return caller_continue;
}

void PgClientConnection::write_ready(DCB* dcb)
{
    mxb_assert(m_dcb == dcb);
    mxb_assert(m_dcb->state() != DCB::State::DISCONNECTED);

    // TODO: Probably some state handling is needed.

    m_dcb->writeq_drain();
}

void PgClientConnection::error(DCB* dcb)
{
    // TODO: Add some logging in case we didn't expect this
    m_session.kill();
}

void PgClientConnection::hangup(DCB* dcb)
{
    // TODO: Add some logging in case we didn't expect this
    m_session.kill();
}

bool PgClientConnection::write(GWBUF&& buffer)
{
    return m_dcb->writeq_append(std::move(buffer));
}

bool PgClientConnection::init_connection()
{
    // The client will send the first message
    return true;
}

void PgClientConnection::finish_connection()
{
    // TODO: Do something?
}

bool PgClientConnection::clientReply(GWBUF&& buffer,
                                     mxs::ReplyRoute& down,
                                     const mxs::Reply& reply)
{
    if (reply.is_complete())
    {
        if (auto trx_state = reply.get_variable(pg::TRX_STATE_VARIABLE); !trx_state.empty())
        {
            auto data = static_cast<PgProtocolData*>(m_session.protocol_data());

            // If the value is anything other than 'I', a transaction is open.
            data->set_in_trx(trx_state[0] != 'I');
        }
    }

    return write(std::move(buffer));
}

bool PgClientConnection::safe_to_restart() const
{
    // TODO: Add support for restarting
    return false;
}

mxs::Parser* PgClientConnection::parser()
{
    return &PgParser::get();
}

size_t PgClientConnection::sizeof_buffers() const
{
    return 0;
}

PgClientConnection::StateMachineRes PgClientConnection::parse_startup_message(const GWBUF& buf)
{
    // TODO: add error messages to the fail cases.
    auto rval = StateMachineRes::ERROR;
    auto buflen = buf.length();
    mxb_assert(buflen >= 8);
    auto ptr = buf.data();
    auto prot_packet_len = pg::consume_uint32(ptr);
    if (prot_packet_len <= 8)
    {
        // too small
    }
    else if (prot_packet_len <= 100000)
    {
        if (prot_packet_len < buflen)
        {
            // Client sent extra data already? Is this allowed?
        }
        else if (prot_packet_len == buflen)
        {
            string_view username;
            string_view database;
            string_view replication;
            // StartupMessage: 4 bytes length, 4 bytes magic number, then pairs of strings.
            uint32_t protocol_version = pg::consume_uint32(ptr);
            if (protocol_version == pg::PROTOCOL_V3_MAGIC)
            {
                bool param_parse_error = false;
                const auto params_begin = ptr;
                const auto end = buf.end();
                while (ptr < end - 1)
                {
                    auto [name_ok, param_name] = pg::consume_zstring(ptr, end);
                    auto [val_ok, param_value] = pg::consume_zstring(ptr, end);
                    if (name_ok && val_ok)
                    {
                        // Only recognize a few parameters. Most of the parameters should be sent as is
                        // to backends.
                        if (param_name == "user")
                        {
                            username = param_value;
                        }
                        else if (param_name == "database")
                        {
                            database = param_value;
                        }
                        else if (param_name == "replication")
                        {
                            replication = param_value;
                        }
                    }
                    else
                    {
                        param_parse_error = true;
                        break;
                    }
                }

                if (!param_parse_error)
                {
                    // There should be one final 0 at the end.
                    if (end - ptr == 1 && *ptr == '\0')
                    {
                        m_session.set_user(username);
                        m_protocol_data->set_default_database(database);
                        m_protocol_data->set_connect_params(params_begin, end);
                        rval = StateMachineRes::DONE;
                    }
                }
            }
        }
        else
        {
            // Not enough data, read again.
            rval = StateMachineRes::IN_PROGRESS;
        }
    }
    else
    {
        // too big
    }
    return rval;
}

bool PgClientConnection::check_user_account_entry()
{
    auto& ses = m_session;
    auto users = static_cast<const PgUserCache*>(ses.service->user_account_cache());
    return users->find_user(ses.user(), ses.client_remote(), m_protocol_data->default_db());
}

bool PgClientConnection::prepare_session()
{
    bool rval = false;
    mxb_assert(m_session.state() == MXS_SESSION::State::CREATED);
    if (m_session.start())
    {
        // Send at least the ReadyForQuery-packet.
        // TODO: Send keydata and parameter status?
        const size_t rdy_len = 1 + 4 + 1;       // Byte1('R'), Int32(8) len, Int8 trx status
        GWBUF ready(rdy_len);
        uint8_t* ptr = ready.data();
        *ptr++ = pg::READY_FOR_QUERY;
        ptr += pg::set_uint32(ptr, 5);
        *ptr++ = 'I';   // trx idle
        write(std::move(ready));
        rval = true;
    }
    else
    {
        // TODO: Send internal error.
        MXB_ERROR("Failed to create session for %s.", m_session.user_and_host().c_str());
    }
    return rval;
}
