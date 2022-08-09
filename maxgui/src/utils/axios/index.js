/*
 * Copyright (c) 2020 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2026-08-08
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */
import ax from 'axios'

const HEADERS = {
    'X-Requested-With': 'XMLHttpRequest',
    'Content-Type': 'application/json',
    'Cache-Control': 'no-cache',
}
const BASE_URL = '/'
const controller = new AbortController()
const CANCEL_MESSAGE = 'canceled'
const abortRequests = () => controller.abort()
function baseConf() {
    return ax.create({
        baseURL: BASE_URL,
        headers: HEADERS,
    })
}
/**
 * Default handler for error response status codes
 */
async function defErrStatusHandler({ store, error }) {
    const { getErrorsArr, delay } = store.vue.$help
    store.commit('SET_SNACK_BAR_MESSAGE', {
        text: getErrorsArr(error),
        type: 'error',
    })
    /* When request is dispatched in a modal, an overlay_type loading will be set,
     * Turn it off before returning error
     */
    if (store.state.overlay_type !== null)
        await delay(600).then(() => store.commit('SET_OVERLAY_TYPE', null))
    return Promise.reject(error)
}

/**
 * @param {Object} payload.store - vuex store instance
 * @param {Object} payload.error - axios error object
 * @returns {Object} - returns an object with error response status codes as key and value as handler function
 */
function baseErrStatusHandlerMap({ store, error }) {
    return {
        401: async function() {
            // cancel all previous requests before logging out
            store.$abortRequests()
            await store.dispatch('user/logout')
        },
        404: async function() {
            await store.router.push('/404')
        },
        null: function() {
            if (error.toString().includes(CANCEL_MESSAGE))
                // request is cancelled by user, so no response is received
                return Promise.reject(error)
            else
                return store.commit('SET_SNACK_BAR_MESSAGE', {
                    text: ['Lost connection to MaxScale, please check if MaxScale is running'],
                    type: 'error',
                })
        },
    }
}

// axios instance for auth endpoint
let authHttp = baseConf()
authHttp.interceptors.request.use(
    config => ({ ...config, signal: controller.signal }),
    error => Promise.reject(error)
)

// axios instance for other endpoints except `/sql`
function http(store) {
    let http = baseConf()

    http.interceptors.request.use(
        config => ({ ...config, signal: controller.signal }),
        error => Promise.reject(error)
    )
    http.interceptors.response.use(
        response => response,
        async error => {
            const { response: { status = null } = {} } = error || {}
            const errStatusHandlerMap = baseErrStatusHandlerMap({ store, error })
            if (Object.keys(errStatusHandlerMap).includes(`${status}`)) {
                await errStatusHandlerMap[status]()
            } else defErrStatusHandler({ store, error })
        }
    )
    return http
}

/**
 *
 * @param {Object} param.store - vuex store
 * @param {Boolean} param.value - is connection busy
 * @param {String} param.sql_conn_id - the connection id that the request is sent
 */
function patchIsConnBusyMap({ store, value, sql_conn_id }) {
    const { id: active_session_id } =
        store.getters['querySession/getSessionByConnId'](sql_conn_id) || {}
    if (active_session_id)
        store.commit('queryConn/PATCH_IS_CONN_BUSY_MAP', {
            id: active_session_id,
            payload: { value },
        })
}
/**
 * This function helps to check if there is a lost connection error that has either
 * 2006 or 2013 errno value and update the corresponding error message object to lost_cnn_err_msg_obj_map state
 * @param {Object} param.res - response of every request from queryHttp axios instance
 * @param {Object} param.store - vuex store
 * @param {String} param.sql_conn_id - the connection id that the request is sent
 */
function analyzeRes({ res, store, sql_conn_id }) {
    const results = store.vue.$typy(res, 'data.data.attributes.results').safeArray
    const lostCnnErrMsgs = results.filter(res => {
        const errno = store.vue.$typy(res, 'errno').safeNumber
        return store.state.app_config.MARIADB_NET_ERRNO.includes(errno)
    })
    if (lostCnnErrMsgs.length) {
        const { id: active_session_id } =
            store.getters['querySession/getSessionByConnId'](sql_conn_id) || {}
        store.commit('queryConn/PATCH_LOST_CNN_ERR_MSG_OBJ_MAP', {
            id: active_session_id,
            payload: { value: lostCnnErrMsgs[0] },
        })
    }
}
function getSqlConnId(url) {
    const matched = /\/sql\/([a-zA-z0-9-]*?)\//g.exec(url) || []
    return matched.length > 1 ? matched[1] : null
}
/**
 * axios instance for `/sql/id/` endpoint.
 * Use this for sql connection endpoint so that the value for
 * is_conn_busy_map can be set accurately.
 * @param {Object} store -vuex store
 * @returns {Object} axios instance
 */
function queryHttp(store) {
    let queryHttp = baseConf()
    queryHttp.interceptors.request.use(
        config => {
            patchIsConnBusyMap({ store, value: true, sql_conn_id: getSqlConnId(config.url) })
            return { ...config, signal: controller.signal }
        },
        error => Promise.reject(error)
    )
    queryHttp.interceptors.response.use(
        response => {
            patchIsConnBusyMap({
                store,
                value: false,
                sql_conn_id: getSqlConnId(response.config.url),
            })
            analyzeRes({ res: response, store, sql_conn_id: getSqlConnId(response.config.url) })
            return response
        },
        async error => {
            const { getErrorsArr } = store.vue.$help
            const { response: { status = null, config: { url = '' } = {} } = {} } = error || {}
            const errStatusHandlerMap = baseErrStatusHandlerMap({ store, error })
            if (status === 404 || status === 503) {
                return store.commit('SET_SNACK_BAR_MESSAGE', {
                    text: [...getErrorsArr(error), 'Please reconnect'],
                    type: 'error',
                })
            } else if (Object.keys(errStatusHandlerMap).includes(`${status}`)) {
                await errStatusHandlerMap[status]()
            } else defErrStatusHandler({ store, error })
            patchIsConnBusyMap({
                store,
                value: false,
                sql_conn_id: getSqlConnId(url),
            })
        }
    )
    return queryHttp
}

export { abortRequests, authHttp, http, queryHttp }
