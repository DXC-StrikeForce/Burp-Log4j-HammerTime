/*
 * Copyright (c) 2021, Freskimo.
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package burp;

import java.sql.Timestamp;

public class TimedRequestResponse {

    private final Timestamp timestamp;
    private final IHttpRequestResponsePersisted httpRequestResponse;

    public TimedRequestResponse(Timestamp timestamp, IHttpRequestResponsePersisted httpRequestResponse) {
        this.timestamp = timestamp;
        this.httpRequestResponse = httpRequestResponse;
    }

    public Timestamp getTimestamp() {
        return timestamp;
    }

    public IHttpRequestResponsePersisted getHttpRequestResponse() {
        return httpRequestResponse;
    }
}