@logged-in
Feature: Display information about a host factory.

  Background:
    Given I create a new user "alice"
    And a host factory for layer "the-layer"
    And I permit user "alice" to "read" it
    And I login as "alice"

  Scenario: The host factory displays the normal resource fields, plus
    the list of layers and tokens. 
    
    Given a host factory token
    When I successfully GET "/resources/cucumber/host_factory/the-layer-factory"
    Then the JSON should be:
    """
    {
      "annotations" : [ ],
      "id": "cucumber:host_factory:the-layer-factory",
      "owner": "cucumber:user:admin",
      "permissions": [ 
        {
          "privilege": "read",
          "role": "cucumber:user:alice"
        }
      ],
      "layers": [
        "cucumber:layer:the-layer"
      ],
      "tokens": [
        {
          "cidr": [],
          "expiration": "@host_factory_token_expiration@",
          "token": "@host_factory_token_token@"
        }
      ]
    }
    """
