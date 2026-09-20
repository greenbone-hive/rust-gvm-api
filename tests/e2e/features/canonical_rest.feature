Feature: Canonical REST journeys
  The gateway exposes a small set of stable journeys that product and
  implementation reviewers can read and execute against the compose stack.

  Scenario: Unauthenticated protected access returns a problem document
    Given the compose-backed gateway is ready
    When a client requests protected targets without authentication
    Then the response is an unauthorized problem document

  Scenario: A gateway session can be created, used, and invalidated
    Given the compose-backed gateway is ready
    When a client creates a gateway session
    Then the session grants protected access
    When the client deletes the gateway session
    Then the deleted bearer token is rejected

  Scenario: A discovery scan produces an observable report export
    Given the compose-backed gateway is ready
    And an active gateway session
    When the client creates a discovery target and task
    And starts the discovery task and waits for completion
    Then the resulting report is linked to the task
    And a JSON export of the report is observable
