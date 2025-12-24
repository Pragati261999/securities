// const swaggerJSDoc = require('swagger-jsdoc');

// const swaggerOptions = {
//     definition: {
//         openapi: '3.0.3',
//         info: {
//             title: 'Secure Task Manager API',
//             version: '1.0.0',
//             description: 'Secure Task Manager REST API documentation',
//         },
//         servers: [
//             {
//                 url: 'http://localhost:4000',
//                 description: 'Local server',
//             },
//         ],
//         components: {
//             securitySchemes: {
//                 BearerAuth: {
//                     type: 'http',
//                     scheme: 'bearer',
//                     bearerFormat: 'JWT',
//                 },
//             },
//         },
//         security: [
//             {
//                 BearerAuth: [],
//             },
//         ],
//     },

//     // Paths to API docs
//     apis: [
//         // './routes/**/*.js',
//         '../routes/**/*.js',
//         '../controllers/**/*.js',
//     ],
// };

// module.exports = swaggerJSDoc(swaggerOptions);



const swaggerJSDoc = require('swagger-jsdoc');
const path = require('path');

const swaggerOptions = {
  definition: {
    openapi: '3.0.3',
    info: {
      title: 'Secure Task Manager API',
      version: '1.0.0',
      description: 'Secure Task Manager REST API documentation',
    },
    servers: [
      {
        url: 'http://localhost:4000',
        description: 'Local server',
      },
    ],
    components: {
      securitySchemes: {
        BearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
    },
    security: [
      {
        BearerAuth: [],
      },
    ],
  },

  // 🔥 THIS IS THE IMPORTANT PART
  apis: [
    path.join(__dirname, '../routes/*.js'),
    path.join(__dirname, '../routes/**/*.js'),
  ],
};

module.exports = swaggerJSDoc(swaggerOptions);

