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

class PgClientConnection : public mxs::ClientConnectionBase
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

    // mxs::ClientConnectionBase
    size_t sizeof_buffers() const override;

private:
    enum class State
    {
        INIT,          // Expecting either SSL request or Startup msg
        SSL_HANDSHAKE, // State if SSL was requested
        AUTH,          // Authentication (not entered if method is trust)
        ROUTE,         // Entered after Startup msg reply has been sent
        ERROR
    };

    State state_init(const GWBUF& gwbuf);
    State state_ssl_handshake(const GWBUF& gwbuf);
    State state_auth(const GWBUF& gwbuf);
    State state_route(GWBUF&& gwbuf);

    State           m_state = State::INIT;
    MXS_SESSION*    m_session;
    mxs::Component* m_down;
};