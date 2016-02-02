'use strict';
/**
 * JSON Schema library
 *
 * @module core/lib/c_l_jsonSchema
 * @license MIT
 * @copyright 2016 Chris Turnbull <https://github.com/christurnbull>
 */
var expressJsonSchema = require('express-jsonschema');

module.exports = function(app, db, lib) {

  // store schema for each route
  app.appCfg.jsonSchema = {};
  app.appCfg.jsonSchema.default = {
    body: {
      type: 'object',
      strict: true,
      properties: {}
    },
    query: {
      type: 'object',
      strict: true,
      properties: {}
    },
    params: {
      type: 'object',
      properties: {}
    }
  };


  /*
   * add a strict mode to json schema validation
   * throws and error if there are properties that are not explicitly stated in the schema
   */
  expressJsonSchema.addSchemaProperties({
    strict: function(value, schema) {
      if (schema.strict) {
        for (var p in value) {
          if (typeof schema.properties[p] === 'undefined') {
            var err = new Error();
            err.name = 'JsonSchemaValidation';
            err.validations = {
              body: [{
                property: p,
                messages: ['illegal property under strict mode']
              }]
            };
            throw err;
          }
        }
      }
    }
  });


  /*
   * middlware
   * lookup the route's schema, apply strict default schema if non set
   * name the function and validate
   */
  return function(id) {
    var schema = {};
    if (!id) {
      schema = app.appCfg.jsonSchema.default;
    } else {
      schema = app.appCfg.jsonSchema[id];
      if (typeof schema.body === 'undefined') {
        schema.body = {
          type: 'object',
          strict: true,
          properties: {}
        };
      }
      if (typeof schema.query === 'undefined') {
        schema.query = {
          type: 'object',
          strict: true,
          properties: {}
        };
      }
      if (typeof schema.params === 'undefined') {
        schema.params = {
          type: 'object',
          properties: {}
        };
      }
    }
    return function jsonSchema(req, res, next) {
      return expressJsonSchema.validate(schema)(req, res, next);
    };
  };
};
