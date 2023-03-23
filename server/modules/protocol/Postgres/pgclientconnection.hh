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

#include "postgresprotocol.hh"
#include <maxscale/protocol2.hh>
#include <maxscale/session.hh>

class PgProtocolData;

class PgClientConnection final : public mxs::ClientConnectionBase
{
public:
    PgClientConnection(MXS_SESSION* pSession, mxs::Component* pComponent);

    // DCBHandler
    void ready_for_reading(DCB* dcb) override;
    void write_ready(DCB* dcb) override;
    void error(DCB* dcb) override;
    void hangup(DCB* dcb) override;

    // mxs::ProtocolConnection
    bool write(GWBUF&& buffer) override;

    // mxs::ClientConnection
    bool init_connection() override;
    void finish_connection() override;
    bool clientReply(GWBUF&& buffer, mxs::ReplyRoute& down, const mxs::Reply& reply) override;
    bool safe_to_restart() const override;
    mxs::Parser* parser() override;

    // mxs::ClientConnectionBase
    size_t sizeof_buffers() const override;

private:
    enum class State
    {
        HANDSHAKE,      /**< Expecting either SSL request or StartupMessage */
        AUTH,           /**< Authenticating */
        ROUTE,          /**< Ready to route queries */
        ERROR           /**< Error, stop session */
    };

    enum class HSState
    {
        INIT,           /**< Initial handshake state */
        STARTUP_MSG,    /**< Expecting client to send StartupMessage */
        FAIL,           /**< Handshake failed */
    };
    bool state_handshake();

    enum class AuthState
    {
        FIND_ENTRY,
        COMPLETE,
        FAIL,
    };
    bool state_auth();
    bool prepare_session();
    bool state_route();

    // Return true if ssl handshake succeeded or is in progress
    bool setup_ssl();

    /** Return type of a lower level state machine */
    enum class StateMachineRes
    {
        IN_PROGRESS,// The function should be called again once more data is available.
        DONE,       // Function is complete, the protocol may advance to next state.
        ERROR,      // Error. The connection should be closed.
    };
    StateMachineRes parse_startup_message(const GWBUF& buf);

    bool check_user_account_entry();

    State           m_state {State::HANDSHAKE};
    HSState         m_hs_state {HSState::INIT};
    AuthState       m_auth_state {AuthState::FIND_ENTRY};
    MXS_SESSION&    m_session;
    PgProtocolData* m_protocol_data {nullptr};
    bool            m_ssl_required {false};
    mxs::Component* m_down;

    // Will be provided by the monitor
    pg::Auth pg_prot_data_auth_method = pg::AUTH_CLEARTEXT;
};
