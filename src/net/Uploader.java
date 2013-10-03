package net;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

public class Uploader {
	public static final String SEND_URL = "https://www.virustotal.com/vtapi/v2/file/scan";
	public static final String RESCAN_URL = "https://www.virustotal.com/vtapi/v2/file/rescan";
	public static final String RETRIEVE_URL = "https://www.virustotal.com/vtapi/v2/file/report";
	private static final String APIKEY = "0eb37e73e7fb03b7fac3b528af6c59c9ae2859709da5c11e6e306c5f784f46fd";
	public static final int BUFFER_SIZE = 8192;
	private File f2upload;
	public Uploader(File fileToUpload) {
		f2upload = fileToUpload;
	}
	
	/**
	 * @return json of response in String
	 * @throws IOException if an I/O exception occurs.
	 */
	public String scan() throws IOException {
		String bound = "41184676334";
		URL url = new URL(SEND_URL);
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setDoOutput(true);
		conn.addRequestProperty("Content-Type", "multipart/form-data; boundary=" + bound);
		OutputStream os = new DataOutputStream(conn.getOutputStream());
		StringBuilder content = new StringBuilder();
		content.append("--" + bound + "\r\nContent-Disposition: form-data; name=\"apikey\"\r\n\r\n" + APIKEY + "\r\n");
		content.append("--" + bound + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + f2upload.getName() + "\"\r\n");
		content.append("Content-Type: application/octet-stream\r\n\r\n");
		os.write(content.toString().getBytes());
		InputStream is = new FileInputStream(f2upload);
		byte[] buffer = new byte[BUFFER_SIZE];
		int read;
		while ((read = is.read(buffer)) >= 0) {
			os.write(buffer, 0, read);
		}
		os.write(("--" + bound + "--").getBytes());
		is.close();
		os.flush();
		os.close();
		InputStream ris = conn.getInputStream();
		BufferedReader br = new BufferedReader(new InputStreamReader(ris));
		String line;
		StringBuilder sb = new StringBuilder();
		while ((line = br.readLine()) != null) {
			sb.append(line);
			sb.append('\n');
		}
		br.close();
		ris.close();
		conn.disconnect();
		return sb.toString();
	}
	
	public String report() throws IOException {
		URL url = new URL(RETRIEVE_URL);
		HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
		conn.setDoOutput(true);
		conn.setRequestMethod("POST");
		OutputStream os = new DataOutputStream(conn.getOutputStream());
		StringBuilder content = new StringBuilder();
		content.append("resource=07824d9ca96ab249cf513d7ac4f203e5596a5edb56be33b91d4905447b28ba40&apikey=" + APIKEY);
		os.write(content.toString().getBytes());
		os.flush();
		os.close();
		InputStream in = conn.getInputStream();
		BufferedReader br = new BufferedReader(new InputStreamReader(in));
		String line;
		StringBuilder sb = new StringBuilder();
		while ((line = br.readLine()) != null) {
			sb.append(line);
			sb.append('\n');
		}
		in.close();
		br.close();
		conn.disconnect();
		return sb.toString();
	}
	public static void main(String[] args) throws Exception {
		Uploader u = new Uploader(new File("Havij.exe"));
		System.out.println(u.report());
	}
}
