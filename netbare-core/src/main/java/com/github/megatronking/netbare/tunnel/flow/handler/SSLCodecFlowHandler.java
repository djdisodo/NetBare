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
package com.github.megatronking.netbare.tunnel.flow.handler;

import android.support.annotation.NonNull;

import com.github.megatronking.netbare.NetBareXLog;
import com.github.megatronking.netbare.tunnel.flow.handler.manager.FlowHandlerManager;
import com.github.megatronking.netbare.tunnel.flow.RequestFlow;
import com.github.megatronking.netbare.tunnel.flow.ResponseFlow;
import com.github.megatronking.netbare.ssl.SSLCodec;
import com.github.megatronking.netbare.ssl.SSLEngineFactory;
import com.github.megatronking.netbare.ssl.SSLRefluxCallback;
import com.github.megatronking.netbare.ssl.SSLRequestCodec;
import com.github.megatronking.netbare.ssl.SSLResponseCodec;

import java.io.IOException;
import java.nio.ByteBuffer;

/**
 * Decodes SSL/TLS packets to plaintext.
 *
 * @author Megatron King
 * @since 2019/4/9 21:39
 */
public abstract
		class SSLCodecFlowHandler<REQUEST_FLOW extends RequestFlow, RESPONSE_FLOW extends ResponseFlow>
        extends PendingIndexedFlowHandler<REQUEST_FLOW, RESPONSE_FLOW>
        implements SSLRefluxCallback<REQUEST_FLOW, RESPONSE_FLOW> {

    private SSLEngineFactory sslEngineFactory;
    private REQUEST_FLOW requestFlow;
    private RESPONSE_FLOW responseFlow;

    private SSLRequestCodec requestCodec;
    private SSLResponseCodec responseCodec;

    private NetBareXLog log;

    protected abstract boolean shouldDecryptRequest(
    		FlowHandlerManager<REQUEST_FLOW, RESPONSE_FLOW> flowHandlerManager
	);
    protected abstract boolean shouldDecryptResponse(
    		FlowHandlerManager<REQUEST_FLOW, RESPONSE_FLOW> flowHandlerManager
	);

    public SSLCodecFlowHandler(SSLEngineFactory engineFactory, REQUEST_FLOW requestFlow, RESPONSE_FLOW responseFlow) {
        this.sslEngineFactory = engineFactory;
        this.requestFlow = requestFlow;
        this.responseFlow = responseFlow;
        requestCodec = new SSLRequestCodec(engineFactory);
        requestCodec.setRequestFlow(requestFlow);
        responseCodec = new SSLResponseCodec(engineFactory);
        responseCodec.setRequest(requestFlow);

        log = new NetBareXLog(requestFlow.protocol(), requestFlow.ip().getHostName(), requestFlow.port());
    }

    @Override
    protected void indexedHandleRequest(
    		@NonNull FlowHandlerManager<REQUEST_FLOW, RESPONSE_FLOW> flowHandlerManager,
			@NonNull ByteBuffer buffer,
			int index
	) throws IOException {
        if (sslEngineFactory == null) {
            // Skip all interceptors
            flowHandlerManager.processFinalRequest(buffer);
            log.w("JSK not installed, skip all interceptors!");
        } else if (shouldDecryptRequest(flowHandlerManager)) {
            decodeRequest(flowHandlerManager, buffer);
            responseCodec.prepareHandshake();
        } else {
            flowHandlerManager.processRequest(buffer);
        }
    }

    @Override
    protected void indexedHandleResponse(
			@NonNull FlowHandlerManager<REQUEST_FLOW, RESPONSE_FLOW> flowHandlerManager,
			@NonNull ByteBuffer buffer,
			int index
	)
            throws IOException {
        if (sslEngineFactory == null) {
            // Skip all interceptors
            flowHandlerManager.processFinalRequest(buffer);
            log.w("JSK not installed, skip all interceptors!");
        } else if (shouldDecryptResponse(flowHandlerManager)) {
            decodeResponse(flowHandlerManager, buffer);
        } else {
            flowHandlerManager.processResponse(buffer);
        }
    }

    @Override
    public void onRequest(REQUEST_FLOW requestFlow, ByteBuffer buffer) throws IOException {
        responseCodec.encode(buffer, new SSLCodec.CodecCallback() {
            @Override
            public void onPending(ByteBuffer buffer) {
            }

            @Override
            public void onProcess(ByteBuffer buffer) {
            }

            @Override
            public void onEncrypt(ByteBuffer buffer) throws IOException {
                // The encrypt getRequest data is sent to remote server
                SSLCodecFlowHandler.this.requestFlow.write(buffer);
            }

            @Override
            public void onDecrypt(ByteBuffer buffer) {
            }
        });
    }

    @Override
    public void onResponse(RESPONSE_FLOW responseFlow, ByteBuffer buffer) throws IOException {
        requestCodec.encode(buffer, new SSLCodec.CodecCallback() {
            @Override
            public void onPending(ByteBuffer buffer) {
            }

            @Override
            public void onProcess(ByteBuffer buffer) {
            }

            @Override
            public void onEncrypt(ByteBuffer buffer) throws IOException {
                // The encrypt response data is sent to proxy server
				SSLCodecFlowHandler.this.responseFlow.write(buffer);
            }

            @Override
            public void onDecrypt(ByteBuffer buffer) {
            }
        });
    }

    private void decodeRequest(
    		final FlowHandlerManager<REQUEST_FLOW, RESPONSE_FLOW> flowHandlerManager,
			ByteBuffer buffer
	) throws IOException {
        // Merge buffers
        requestCodec.decode(buildRequestBuffer(buffer),
                new SSLCodec.CodecCallback() {
                    @Override
                    public void onPending(ByteBuffer buffer) {
                        addRequestBuffer(buffer);
                    }

                    @Override
                    public void onProcess(ByteBuffer buffer) throws IOException {
                        flowHandlerManager.processFinalRequest(buffer);
                    }

                    @Override
                    public void onEncrypt(ByteBuffer buffer) throws IOException {
                        SSLCodecFlowHandler.this.responseFlow.write(buffer);
                    }

                    @Override
                    public void onDecrypt(ByteBuffer buffer) throws IOException {
                        flowHandlerManager.processRequest(buffer);
                    }
                });
    }


    private void decodeResponse(
    		final FlowHandlerManager<REQUEST_FLOW, RESPONSE_FLOW> flowHandlerManager,
			ByteBuffer buffer
	) throws IOException {
        // Merge buffers
        responseCodec.decode(buildResponseBuffer(buffer),
                new SSLCodec.CodecCallback() {
                    @Override
                    public void onPending(ByteBuffer buffer) {
                        addResponseBuffer(buffer);
                    }

                    @Override
                    public void onProcess(ByteBuffer buffer) throws IOException {
						flowHandlerManager.finishResponse(buffer);
                    }

                    @Override
                    public void onEncrypt(ByteBuffer buffer) throws IOException {
                        requestFlow.write(buffer);
                    }

                    @Override
                    public void onDecrypt(ByteBuffer buffer) throws IOException {
						flowHandlerManager.processResponse(buffer);
                    }

                });
    }

}