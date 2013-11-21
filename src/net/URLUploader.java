package net;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

import tools.StringJsonParser;

public class URLUploader {
	public static final String SEND_URL = "https://www.virustotal.com/vtapi/v2/url/scan";
	public static final String RETRIEVE_URL = "https://www.virustotal.com/vtapi/v2/url/report";
	private static final String APIKEY = "0eb37e73e7fb03b7fac3b528af6c59c9ae2859709da5c11e6e306c5f784f46fd";
	
	private String url;
	private String scan_id;
	private boolean analysed = false;
	
	public URLUploader(String url) {
		this.url = url;
	}
	
	/**
	 * upload url to VirusTotal
	 * 
	 * @return json of response in String
	 * @throws IOException
	 *             if an I/O exception occurs.
	 */
	public String scan() throws IOException {
		URL toscan = new URL(SEND_URL);
		HttpsURLConnection conn = (HttpsURLConnection) toscan.openConnection();
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		String param = "url=" + url + "&apikey=" + APIKEY;
		try (OutputStream out = conn.getOutputStream();) {
			out.write(param.getBytes());
		}
		StringBuilder sb = new StringBuilder();
		try(BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));) {
			String line;
			while ((line = br.readLine()) != null) {
				sb.append(line);
				sb.append('\n');
			}
		}
		conn.disconnect();
		return sb.toString();
	}
	
	/**
	 * @param json
	 *            the json String returned by scan
	 */
	public void analyseScanId(String json) {
		scan_id = StringJsonParser.getValue(json, "scan_id").substring(1);
		scan_id = scan_id.substring(0, scan_id.length() - 1);
		analysed = true;
	}
	
	/**
	 * get the result of scan if scan is finished.
	 * 
	 * @return json of response in String
	 * @throws IOException
	 *             if an I/O exception occurs.
	 */
	public String getReport() throws IOException {
		String resource = analysed ? scan_id : url;
		String param = "resource=" + resource + "&apikey=" + APIKEY;
		System.out.println(param);
		URL toscan = new URL(RETRIEVE_URL);
		HttpsURLConnection conn = (HttpsURLConnection) toscan.openConnection();
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		try (OutputStream out = conn.getOutputStream();) {
			out.write(param.getBytes());
		}
		StringBuilder sb = new StringBuilder();
		try(BufferedReader br = new BufferedReader(new InputStreamReader(conn.getInputStream()));) {
			String line;
			while ((line = br.readLine()) != null) {
				sb.append(line);
				sb.append('\n');
			}
		}
		conn.disconnect();
		return sb.toString();
	}
	
	public static void main(String[] args) throws Exception {
		URLUploader u = new URLUploader("http://buding.yxbao.com/MDK2modfiy.exe");
		u.scan_id = "f9b7de4e12d3ef72a1272436a47f4d503e11d48fa216ee9712c69250a1caa947-1385003874";
		u.analysed = true;
		System.out.println(u.getReport());
	}
}
