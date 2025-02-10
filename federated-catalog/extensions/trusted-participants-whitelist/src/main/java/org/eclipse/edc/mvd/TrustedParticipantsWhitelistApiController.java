/*
 *  Copyright (c) 2024 Fraunhofer Institute for Software and Systems Engineering
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Fraunhofer Institute for Software and Systems Engineering - initial implementation
 *
 */

package org.eclipse.edc.mvd;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.edc.mvd.model.DataTrusteeRequest;
import org.eclipse.edc.mvd.model.NegotiationRequest;
import org.eclipse.edc.mvd.model.NegotiationResponse;
import org.eclipse.edc.mvd.model.Participant;
import org.eclipse.edc.mvd.model.TrustedParticipantsResponse;
import org.eclipse.edc.mvd.util.HashUtil;
import org.eclipse.edc.spi.monitor.Monitor;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.UriInfo;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * TrustedParticipantsWhitelistApiController provides endpoints
 * to maintain the whitelist for selecting data trustees
 */
@Consumes({ MediaType.APPLICATION_JSON })
@Produces({ MediaType.APPLICATION_JSON })
@Path("/trusted-participants")
public class TrustedParticipantsWhitelistApiController {

  private final Monitor monitor;
  private final TrustedParticipantsWhitelist trustedList;
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;

  /**
   * Constructor for TrustedParticipantsWhitelistApiController.
   *
   * @param monitor The monitor used for logging and monitoring.
   */
  public TrustedParticipantsWhitelistApiController(Monitor monitor) {
    this.monitor = monitor;
    this.trustedList = TrustedParticipantsWhitelist.getInstance();
    this.httpClient = HttpClient.newHttpClient();
    this.objectMapper = new ObjectMapper();
  }

  /**
   * Checks the health of the service.
   *
   * @return A string indicating the health status.
   */
  @GET
  @Path("health")
  public String checkHealth() {
    monitor.info("Received a health request");
    return "{\"response\":\"Web server running on Connector and ready for requests\"}";
  }

  /**
   * Adds a trusted participant to the whitelist.
   *
   * @return A response indicating the outcome.
   */
  @POST
  @Path("add")
  public String addTrustedParticipant(Participant participant) {
    monitor.info("Adding trusted participant: " + participant.getName());
    boolean isAdded = trustedList.addTrustedParticipant(participant);
    if (isAdded) {
      return "{\"response\":\"Participant added successfully\"}";
    } else {
      return "{\"response\":\"Participant already exists\"}";
    }
  }

  /**
   * Retrieves a list of trusted participants.
   *
   * @return A list of trusted participants.
   */
  @GET
  @Path("list")
  public TrustedParticipantsResponse getTrustedParticipants() {
    monitor.info("Retrieving trusted participants");
    List<Participant> participants = trustedList.getTrustedParticipants();
    String hash = "";
    try {
      hash = HashUtil.computeHash(participants);
    } catch (NoSuchAlgorithmException e) {
      monitor.warning("Failed to compute Hash: " + e.getMessage());
    }
    return new TrustedParticipantsResponse(participants, hash);
  }

  /**
   * Removes a trusted participant from the whitelist.
   *
   * @return A response indicating the outcome.
   */
  @DELETE
  @Path("remove")
  public String removeTrustedParticipant(Participant participant) {
    monitor.info("Removing trusted participant: " + participant.getName());
    if (trustedList.removeTrustedParticipant(participant)) {
      return "{\"response\":\"Participant removed successfully\"}";
    } else {
      return "{\"response\":\"Participant not found\"}";
    }
  }

  /**
   * Initiates a negotiation with another system to determine common trusted
   * participants.
   *
   * @param counterPartyUrl The URL of the counterparty to negotiate with.
   * @return The result of the negotiation.
   */
//  @POST
//  @Path("negotiate/{counterPartyUrl}")
//  public String initiateNegotiation(@PathParam("counterPartyUrl") String counterPartyUrl) {
//    try {
//      List<Participant> participants = trustedList.getTrustedParticipants();
//      String hash = HashUtil.computeHash(participants);
//      NegotiationInitiateRequest negotiationInitiateRequest = new NegotiationInitiateRequest(participants, hash);
//      String requestBody = objectMapper.writeValueAsString(negotiationInitiateRequest);
//      HttpRequest request = HttpRequest.newBuilder()
//          .uri(URI.create(counterPartyUrl))
//          .header("Content-Type", "application/json")
//          .POST(HttpRequest.BodyPublishers.ofString(requestBody))
//          .build();
//      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//      monitor.info("Negotiation initiated with: " + counterPartyUrl + "; Response: " + response.body());
//      return response.body();
//    } catch (Exception e) {
//      monitor.warning("Failed to initiate negotiation with " + counterPartyUrl + ": " + e.getMessage());
//      return "{\"error\":\"Failed to send negotiation request: " + e.getMessage() + "\"}";
//    }
//  }

//  @POST
//  @Path("negotiate/{counterPartyUrl}")
//  public String initiateNegotiation(@PathParam("counterPartyUrl") String counterPartyUrl) {
//    try {
//      // Get the list of trusted participants from your whitelist
//      List<Participant> trustedDataTrustees = trustedList.getTrustedParticipants();
//
//      // Compute the hash of the trusted participants
//      String hash = HashUtil.computeHash(trustedDataTrustees);
//
//      // Define the data source and data sink participants
//      Participant dataSource = new Participant("participant1", "name1", "http://localhost:9999/protocol");
//      Participant dataSink = new Participant("participant2", "name2","http://localhost:8888/protocol");
//
//      // List of assets involved in the negotiation
//      List<String> assets = List.of("asset1", "asset2");
//
//      // Create the NegotiationRequest object
//      NegotiationRequest negotiationRequest = new NegotiationRequest(
//              dataSource,
//              dataSink,
//              trustedDataTrustees,
//              assets,
//              hash
//      );
//
//      // Serialize the NegotiationRequest to JSON
//      String requestBody = objectMapper.writeValueAsString(negotiationRequest);
//
//      // Build the HTTP request to the counterparty's receive-negotiation endpoint
//      HttpRequest request = HttpRequest.newBuilder()
//              .uri(URI.create(counterPartyUrl))
//              .header("Content-Type", "application/json")
//              .POST(HttpRequest.BodyPublishers.ofString(requestBody))
//              .build();
//
//      // Send the request and get the response
//      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
//
//      monitor.info("Negotiation initiated with: " + counterPartyUrl + "; Response: " + response.body());
//
//      // Return the response from the counterparty
//      return response.body();
//    } catch (Exception e) {
//      monitor.warning("Failed to initiate negotiation with " + counterPartyUrl + ": " + e.getMessage());
//      return "{\"error\":\"Failed to send negotiation request: " + e.getMessage() + "\"}";
//    }
//  }

  @POST
  @Path("negotiate/{counterPartyUrl}")
  public String initiateNegotiation(@PathParam("counterPartyUrl") String counterPartyUrl, @Context UriInfo uriInfo) {
    try {
      // Get the list of trusted participants from your whitelist
      List<Participant> trustedDataTrustees = trustedList.getTrustedParticipants();

      // Compute the hash of the trusted participants
      String hash = HashUtil.computeHash(trustedDataTrustees);

      // Extract dataSource from the request URL before "/trusted-participants"
//      String requestUri = uriInfo.getRequestUri().toString();
//      int negotiateIndex = requestUri.indexOf("/trusted-participants/");
//      String baseUrl = requestUri.substring(0, negotiateIndex);
      String requestUri = uriInfo.getRequestUri().toString();
      int negotiateIndex = requestUri.indexOf("/negotiate/");
      int trustedParticipantsIndex = requestUri.indexOf("/api/trusted-participants");
      String dataSinkUrl;
      if (trustedParticipantsIndex != -1) {
        dataSinkUrl = requestUri.substring(0, trustedParticipantsIndex + "/api/trusted-participants".length());
      } else {
        dataSinkUrl = requestUri.substring(0, negotiateIndex) + "/api/trusted-participants";
      }
      Participant dataSink = new Participant(null, "consumer", dataSinkUrl);

      // Decode counterPartyUrl to get dataSink URL
//      String decodedCounterPartyUrl = URLDecoder.decode(counterPartyUrl, StandardCharsets.UTF_8.name());
      String dataSourceUrl = counterPartyUrl.substring(0, counterPartyUrl.indexOf("/receive-negotiation"));

      Participant dataSource = new Participant(null, "provider", dataSourceUrl);

      // Log the request parameters
//      monitor.info("InitiateNegotiation called with parameters:");
//      monitor.info("Encoded CounterPartyUrl: " + counterPartyUrl);
//      monitor.info("Decoded CounterPartyUrl: " + decodedCounterPartyUrl);
//      monitor.info("DataSource URL: " + dataSource.getUrl());
//      monitor.info("DataSink URL: " + dataSink.getUrl());
      // List of assets involved in the negotiation
      List<String> assets = List.of("asset1", "asset2");

      // Create the NegotiationRequest object
      NegotiationRequest negotiationRequest = new NegotiationRequest(
              dataSource,
              dataSink,
              trustedDataTrustees,
              assets,
              hash
      );

      // Serialize the NegotiationRequest to JSON
      String requestBody = objectMapper.writeValueAsString(negotiationRequest);

      // Build the HTTP request to the counterparty's receive-negotiation endpoint
      HttpRequest request = HttpRequest.newBuilder()
              .uri(URI.create(counterPartyUrl))
              .header("Content-Type", "application/json")
              .POST(HttpRequest.BodyPublishers.ofString(requestBody))
              .build();

      // Send the request and get the response
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

      monitor.info("Negotiation initiated with: " + counterPartyUrl + "; Response: " + response.body());

      // Deserialize negotiation response
      NegotiationResponse negotiationResponse = objectMapper.readValue(response.body(), NegotiationResponse.class);

      // Check if a trusted data trustee was selected
      Participant chosenDataTrustee = negotiationResponse.trustedDataTrustee();
      if (chosenDataTrustee != null && chosenDataTrustee.getUrl() != null && !chosenDataTrustee.getUrl().isEmpty()) {
        // Prepare the notification request
        String notificationUrl = chosenDataTrustee.getUrl() + "/notify";
        DataTrusteeRequest dataTrusteeRequest = new DataTrusteeRequest(
                negotiationResponse.dataSource(),
                negotiationResponse.dataSink(),
                negotiationResponse.assets()
        );
        String notificationBody = objectMapper.writeValueAsString(dataTrusteeRequest);

        // Send the notification
        HttpRequest notificationRequest = HttpRequest.newBuilder()
                .uri(URI.create(notificationUrl))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(notificationBody))
                .build();

        HttpResponse<String> notificationResponse = httpClient.send(notificationRequest, HttpResponse.BodyHandlers.ofString());
        monitor.info("Notification sent to " + chosenDataTrustee.getName() + "; Response: " + notificationResponse.body());
      } else {
        monitor.warning("No commonly trusted data trustee found.");
      }


      // Return the response from the counterparty
      return response.body();
    } catch (Exception e) {
      monitor.warning("Failed to initiate negotiation with " + counterPartyUrl + ": " + e.getMessage());
      return "{\"error\":\"Failed to send negotiation request: " + e.getMessage() + "\"}";
    }
  }

  /**
   * Receives a negotiation request from another participant, matches trusted
   * participants, and chooses one for data transfer.
   *
   * @param negotiationRequest The list of trusted participants from the
   *                           negotiation initiator.
   * @return A response with matched participants and the chosen participant.
   */
  @POST
  @Path("receive-negotiation")
  public String receiveNegotiation(NegotiationRequest negotiationRequest) {
    monitor.info("Received negotiation request");
    try {
      String receivedHash = negotiationRequest.hash();
      List<Participant> participants = negotiationRequest.trustedDataTrustees();
      String computedHash = HashUtil.computeHash(participants);
      if (!computedHash.equals(receivedHash)) {
        monitor.warning("Hash mismatch: possible data tampering detected.");
        return "{\"error\":\"Hash mismatch: possible data tampering detected.\"}";
      }
    } catch (NoSuchAlgorithmException e) {
      monitor.warning("Failed to compute hash: " + e.getMessage());
      return "{\"error\":\"Failed to compute hash: " + e.getMessage() + "\"}";
    }
//    List<Participant> matches = trustedList.getTrustedParticipants().stream()
//        .filter(negotiationRequest.trustedDataTrustees()::contains)
//        .toList();
    List<Participant> matches = trustedList.getTrustedParticipants().stream()
            .filter(p -> negotiationRequest.trustedDataTrustees().stream()
                    .anyMatch(nrp -> p.getName().equals(nrp.getName()) && p.getUrl().equals(nrp.getUrl())))
            .toList();
    // Select the first matched participant for simplicity, can implement a better
    // selection logic
    Participant chosenDataTrustee = matches.isEmpty() ? null : matches.get(0);
    if (chosenDataTrustee != null && chosenDataTrustee.getUrl()!= null && !chosenDataTrustee.getUrl().isEmpty()) {
      try {
        String notificationUrl = chosenDataTrustee.getUrl() + "/notify";
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(notificationUrl))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(new DataTrusteeRequest(
                negotiationRequest.dataSource(),
                negotiationRequest.dataSink(),
                negotiationRequest.assets()))))
            .build();
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        monitor.info("Notification sent to " + chosenDataTrustee.getName() + "; Response: " + response.body());
      } catch (Exception e) {
        monitor.warning("Failed to send notification to " + chosenDataTrustee.getName() + ": " + e.getMessage());
      }
      var negotiationResponse = new NegotiationResponse(
          negotiationRequest.dataSource(),
          negotiationRequest.dataSink(),
          chosenDataTrustee,
          negotiationRequest.assets());
      try {
        // Serialize the negotiation response to JSON
        String responseBody = objectMapper.writeValueAsString(negotiationResponse);
        return responseBody;
      } catch (Exception e) {
        monitor.warning("Failed to serialize negotiation response: " + e.getMessage());
        return "{\"error\":\"Failed to serialize negotiation response: " + e.getMessage() + "\"}";
      }
//      return "{\"dataSource\":" + negotiationResponse.dataSource() +
//          ", \"dataSink\":\"" + negotiationResponse.dataSink() +
//          ", \"trustedDataTrustee\":\"" + chosenDataTrustee +
//          ", \"assets\":\"" + negotiationResponse.assets() +
//          "\"}";
    } else {
      return "{\"trustedDataTrustee\":[], \"message\":\"No commonly trusted data trustee found\"}";
    }
  }

  @POST
  @Path("notify")
  public Response receiveNotification(String notification) {
    monitor.info("Received notification: " + notification);
    return Response.ok("{\"message\":\"Notification received\"}").build();
  }
}