class Token {
    constructor() {
      this.char_Token = new Map();
      this.word_Token = new Map();
      
      this.word_Token.set('select', 'SELECT');
      this.word_Token.set('from', 'FROM');
      this.word_Token.set('where', 'WHERE');
      this.word_Token.set('and', 'AND');
      this.word_Token.set('or', 'OR');
      this.word_Token.set('insert', 'INSERT');
      this.word_Token.set('update', 'UPDATE');
      this.word_Token.set('delete', 'DELETE');

      this.char_Token.set('=', 'EQUAL');
      this.char_Token.set(';', 'SEMI');
      this.char_Token.set('(', 'LEFT_PAREN');
      this.char_Token.set(')', 'RIGHT_PAREN');
      this.char_Token.set('\'', 'QUOTE');
      this.char_Token.set('"', 'DOUBLE_QUOTE');
    }
  
    getToken(value) {
      return this.char_Token.get(value) || this.word_Token.get(value.toLowerCase());
    }
  }

  class TernaryNode {
    constructor(token, taintedString = null) {
      this.token = token;           
      this.taintedString = taintedString;  
      this.leftChild = null;       
      this.middleChild = null;        
      this.rightChild = null;        
    }
  }
  
  class SQLInjectionDetector {
    constructor() {
      this.token = new Token();
      this.currentPos = 0;
      this.sqlString = '';
    }
  
    lexicalAnalysis(sql) {
      const tokens = [];
      let currentToken = '';
      
      for(let i = 0; i < sql.length; i++) {
        const char = sql[i];
        
        if (char === ' ' || char === '\n' || char === '\t') {
          if (currentToken) {
            const tokenType = this.token.getToken(currentToken);
            tokens.push({
              value: currentToken,
              type: tokenType || 'IDENTIFIER'
            });
            currentToken = '';
          }
          continue;
        }

        if (this.token.char_Token.has(char)) {
          if (currentToken) {
            const tokenType = this.token.getToken(currentToken);
            tokens.push({
              value: currentToken,
              type: tokenType || 'IDENTIFIER'
            });
            currentToken = '';
          }
          tokens.push({
            value: char,
            type: this.token.getToken(char)
          });
          continue;
        }
        
        currentToken += char;
      }
      
      if (currentToken) {
        const tokenType = this.token.getToken(currentToken);
        tokens.push({
          value: currentToken,
          type: tokenType || 'IDENTIFIER'
        });
      }
      
      return tokens;
    }

    buildTernaryTree(tokens, userInputs) {
      const root = new TernaryNode('ROOT');
      let currentNode = root;
      
      for (let i = 0; i < tokens.length; i++) {
        const token = tokens[i];

        const isTainted = userInputs.some(input => 
          token.value.includes(input) || input.includes(token.value)
        );
        
        if (isTainted) {
          const taintedNode = new TernaryNode(token.type, token.value);

          if (!currentNode.middleChild) {
            currentNode.middleChild = taintedNode;
          }
          else if (!currentNode.leftChild) {
            currentNode.leftChild = taintedNode;
          }
          else {
            let siblingNode = currentNode.leftChild;
            while (siblingNode.leftChild) {
              siblingNode = siblingNode.leftChild;
            }
            siblingNode.leftChild = taintedNode;
          }
        }
        
        if (['SELECT', 'FROM', 'WHERE', 'AND', 'OR'].includes(token.type)) {
          const newNode = new TernaryNode(token.type);
          currentNode.rightChild = newNode;
          currentNode = newNode;
        }
      }
      
      return root;
    }
  
    detectInjection(root) {
      const taintedPaths = [];
      
      const visit = (node, path = []) => {
        if (!node) return;
        
        path.push(node.token);
        
        // If node has tainted string, record the path
        if (node.taintedString) {
          taintedPaths.push({
            path: [...path],
            taintedString: node.taintedString
          });
        }
        
        // Visit brother nodes (left)
        if (node.leftChild) {
          visit(node.leftChild, [...path]);
        }
        
        // Visit child block (right)
        if (node.rightChild) {
          visit(node.rightChild, [...path]);
        }
        
        // Check middle node for tainted data
        if (node.middleChild) {
          visit(node.middleChild, [...path]);
        }
      };
      
      visit(root);
      
      // Analyze tainted paths for injection patterns
      return this.analyzeTaintedPaths(taintedPaths);
    }
  
    // Analyze tainted paths for SQL injection patterns
    analyzeTaintedPaths(taintedPaths) {
      const dangerous_patterns = [
        'OR 1=1',
        'OR TRUE',
        '--',
        ';',
        'UNION SELECT',
        'DROP TABLE',
        'DELETE FROM',
        'INSERT INTO',
        'EXEC(',
        'EXECUTE('
      ];
      
      for (const {taintedString} of taintedPaths) {
        // Check for dangerous patterns in tainted strings
        for (const pattern of dangerous_patterns) {
          if (taintedString.toUpperCase().includes(pattern)) {
            return {
              isInjection: true,
              reason: `Dangerous pattern detected: ${pattern}`,
              taintedString
            };
          }
        }
        
        // Check for quote escaping
        if ((taintedString.match(/'/g) || []).length % 2 !== 0 ||
            (taintedString.match(/"/g) || []).length % 2 !== 0) {
          return {
            isInjection: true,
            reason: 'Quote escaping detected',
            taintedString
          };
        }
      }
      
      return {
        isInjection: false
      };
    }
  
    // Main detection method
    detect(sql, userInputs) {
      // Step 1: Lexical Analysis
      const tokens = this.lexicalAnalysis(sql);
      
      // Step 2: Build Ternary Tree
      const tree = this.buildTernaryTree(tokens, userInputs);
      
      // Step 3: Detect Injection
      return this.detectInjection(tree);
    }
  }
  
  // Example usage:
  const detector = new SQLInjectionDetector();
  
  // Test normal query
  const normalQuery = "SELECT * FROM users WHERE username = 'john' AND password = 'pass123'";
  const normalInputs = ['john', 'pass123'];
  console.log('Normal query check:', detector.detect(normalQuery, normalInputs));
  
  // Test injection attempt
  const injectionQuery = "SELECT * FROM users WHERE username = 'admin' OR 1=1--' AND password = 'anything'";
  const injectionInputs = ["admin' OR 1=1--", 'anything'];
  console.log('Injection check:', detector.detect(injectionQuery, injectionInputs));


  module.exports = SQLInjectionDetector;
