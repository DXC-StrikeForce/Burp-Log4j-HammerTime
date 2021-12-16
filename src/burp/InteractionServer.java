/*
 * Copyright (c) 2021, Freskimo.
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class InteractionServer implements Runnable, IExtensionStateListener {

    private IBurpExtenderCallbacks callbacks;
    private ConcurrentHashMap<String, TimedRequestResponse> processedRequestResponse;
    private IBurpCollaboratorClientContext collaboratorContext;

    private PrintWriter stdout;
    private PrintWriter stderr;

    private static final DateFormat DATE_FORMAT = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");

    private static final String issueName = "Apache Log4j RCE vulnerability";
    private static final String issueDetails = "The Collaborator Server received a %s interaction from IP address %s at %s (payload: %s)";
    private static final String remediation = "If the RCE Log4j vulnerability (CVE-2021-44228 or CVE-2021-45046) is detected, update to fixed version 2.16.0 to avoid exploitation. Another option is to add Java parameter -Dlog4j2.formatMsgNoLookups=true in order to change system property log4j2.formatMsgNoLookups to true in versions 2.10 to 2.14.1, or remove JndiLookup class from the classpath. That said the best option is to update to the new, secure version — 2.16.";
    private static final String severity = "High";
    private static final String confidence = "Certain";

    // Thread options
    private static final int SLEEP_TIME = 5 * 1000; // 5 sec
    private volatile boolean isPaused = false;

    // Purge ConcurrentHashMap
    public static final int QUEUE_TIME_LIMIT = 1 * 60 * 1000; // 2 minutes

    public InteractionServer(IBurpExtenderCallbacks callbacks, ConcurrentHashMap<String, TimedRequestResponse> processedRequestResponse, IBurpCollaboratorClientContext initialCollaboratorContext) {
        if(callbacks == null ||
                processedRequestResponse == null ||
                initialCollaboratorContext == null){
            throw new NullPointerException("Constructor values are empty!");
        }

        this.callbacks = callbacks;
        this.processedRequestResponse = processedRequestResponse;
        this.collaboratorContext = initialCollaboratorContext;

        // Initialize stdout and stderr
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        // Init  Timezone
        DATE_FORMAT.setTimeZone(TimeZone.getDefault());
    }

    @Override
    public void run() {
        stdout.println("[+] Collaborator Interaction Server Thread started");
        try {
            while (!isPaused) {
                Thread.sleep(SLEEP_TIME);

                // Check Burp Collaborator
                collaboratorContext.fetchAllCollaboratorInteractions()
                        .forEach(i -> {
                            stdout.println("[+] Checking interactionID: " + i.getProperty("interaction_id"));
                            processInteraction(i);

                        });

                // Purge old entries
                processedRequestResponse.entrySet().stream()
                        .filter(e -> e.getValue().getTimestamp().before(new Timestamp(System.currentTimeMillis() - QUEUE_TIME_LIMIT)))
                        .forEach(i -> {
                            stdout.println("[+] Purging interactionID: " + i.getKey());
                            processedRequestResponse.remove(i.getKey());
                        });
            }
        }
        catch (IllegalStateException e) {
            stdout.println("Burp Collaborator is disabled");
        }
        catch (InterruptedException e) {
            stdout.println("Interrupted");
        }
        catch (Exception e) {
            stdout.println("Error fetching/handling interactions: "+e.getMessage());
        }

        stdout.println("Shutting down collaborator monitor thread");
    }

    public void processInteraction(IBurpCollaboratorInteraction interaction) {
        String interaction_id = interaction.getProperty("interaction_id");
        TimedRequestResponse timedRequestResponse = processedRequestResponse.get(interaction_id);
        if(timedRequestResponse != null) {
            String localTimestamp = convertTimeStampToLocalTime(interaction.getProperty("time_stamp"));
            String collaborator_full = interaction.getProperty("interaction_id") + "." +
                    collaboratorContext.getCollaboratorServerLocation();

            IHttpRequestResponsePersisted requestResponse = timedRequestResponse.getHttpRequestResponse();
            List<int[]> matches = getMatches(requestResponse.getRequest(), collaborator_full.getBytes());

            CustomScanIssue newIssue = new CustomScanIssue(
                    requestResponse.getHttpService(),
                    callbacks.getHelpers().analyzeRequest(requestResponse).getUrl(),
                    new IHttpRequestResponse[]{callbacks.applyMarkers(requestResponse, matches, null)},
                    this.issueName,
                    this.severity,
                    this.confidence,
                    String.format(this.issueDetails, interaction.getProperty("type"), interaction.getProperty("client_ip"), localTimestamp, collaborator_full),
                    this.remediation);

            String urlPrefix = newIssue.getUrl().toString().replaceFirst("\\?.*$", "");
            if (!BurpExtender.hasDuplicatedIssue(callbacks.getScanIssues(urlPrefix), newIssue)) {
                callbacks.addScanIssue(newIssue);
            }
        }
    }

    public void pause() {
        this.isPaused = true;
        stdout.println("Stopping Collaborator interactions polling");
    }

    public void unPause() {
        this.isPaused = false;
        stdout.println("Restarting Collaborator interactions polling");
    }

    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = callbacks.getHelpers().indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }

    private String convertTimeStampToLocalTime(String dateStr) {
        String localTimestamp = "";
        try {
            Date date = DATE_FORMAT.parse(dateStr);
            localTimestamp = DATE_FORMAT.format(date);
        } catch (Exception e) {
            localTimestamp = dateStr;
        }
        return localTimestamp;
    }

    @Override
    public void extensionUnloaded() {
        stdout.println("Extension unloading - triggering abort");
        this.pause();
        Thread.currentThread().interrupt();
    }
}