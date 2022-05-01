//    Copyright 2019 Tremolo Security, Inc.
// 
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
// 
//        http://www.apache.org/licenses/LICENSE-2.0
// 
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.


package com.tremolosecurity.kubernetes.artifacts.obj;


import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.conn.BasicHttpClientConnectionManager;

/**
 * Utility class representing an http connection
 */
public class HttpCon {
	
	
	
	BasicHttpClientConnectionManager bcm;
	CloseableHttpClient http;
	
	/**
	 * Get client manager
	 * @return
	 */
	public BasicHttpClientConnectionManager getBcm() {
		return bcm;
	}

	/**
	 * Set client manager
	 * @param bcm
	 */
	public void setBcm(BasicHttpClientConnectionManager bcm) {
		this.bcm = bcm;
	}

	/**
	 * Get HTTP client
	 * @return
	 */
	public CloseableHttpClient getHttp() {
		return http;
	}

	/** 
	 * Set http client
	 */
	public void setHttp(CloseableHttpClient http) {
		this.http = http;
	}
	
	
}


