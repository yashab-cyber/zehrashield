# ZehraShield Developer Guide

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Development Environment](#development-environment)
3. [Code Structure](#code-structure)
4. [API Development](#api-development)
5. [Security Layer Development](#security-layer-development)
6. [Machine Learning Integration](#machine-learning-integration)
7. [Web Interface Development](#web-interface-development)
8. [Testing](#testing)
9. [Deployment](#deployment)
10. [Contributing](#contributing)

## Architecture Overview

ZehraShield is built using a modular, multi-layer architecture designed for enterprise security:

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Management Console                    │
├─────────────────────────────────────────────────────────────┤
│                         REST API                            │
├─────────────────────────────────────────────────────────────┤
│                    Firewall Engine                          │
├─────────────────────────────────────────────────────────────┤
│  Layer 1  │  Layer 2  │  Layer 3  │  Layer 4  │  Layer 5  │ Layer 6  │
│  Packet   │   App     │  IDS/IPS  │  Threat   │    NAC    │   SIEM   │
│ Filtering │ Gateway   │           │   Intel   │           │Integration│
├─────────────────────────────────────────────────────────────┤
│              Machine Learning Engine                        │
├─────────────────────────────────────────────────────────────┤
│         Configuration │    Logging    │    Storage         │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

1. **Firewall Engine**: Central orchestrator for all security layers
2. **Security Layers**: Modular security components (Layers 1-6)
3. **ML Engine**: Machine learning for threat detection and analysis
4. **Web Console**: Flask-based management interface
5. **API Layer**: RESTful API for integration and management
6. **Configuration Manager**: Centralized configuration handling
7. **Logger**: Security event logging and management

## Development Environment

### Prerequisites

- Python 3.8+ with pip
- Node.js 14+ (for frontend development)
- Git
- Linux development environment (Ubuntu 20.04+ recommended)

### Setup

1. **Clone Repository**:
   ```bash
   git clone https://github.com/yashab-cyber/zehrashield.git
   cd zehrashield
   ```

2. **Create Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Development Tools**:
   ```bash
   pip install pytest pytest-cov flake8 black isort mypy
   ```

5. **Initialize Configuration**:
   ```bash
   cp config/firewall.json.example config/firewall.json
   ```

6. **Run Tests**:
   ```bash
   python -m pytest tests/ -v
   ```

### Development Workflow

1. **Create Feature Branch**:
   ```bash
   git checkout -b feature/new-feature
   ```

2. **Code Development**:
   - Follow PEP 8 style guidelines
   - Add type hints where appropriate
   - Write unit tests for new functionality
   - Update documentation

3. **Code Quality Checks**:
   ```bash
   # Format code
   black src/
   isort src/
   
   # Lint code
   flake8 src/
   
   # Type checking
   mypy src/
   ```

4. **Run Tests**:
   ```bash
   python -m pytest tests/ --cov=src/ --cov-report=html
   ```

5. **Submit Pull Request**:
   - Ensure all tests pass
   - Include comprehensive description
   - Reference any related issues

## Code Structure

```
zehrashield/
├── src/
│   ├── core/                    # Core components
│   │   ├── config_manager.py    # Configuration management
│   │   ├── logger.py           # Logging system
│   │   └── firewall_engine.py  # Main orchestrator
│   ├── layers/                 # Security layers
│   │   ├── layer1_packet_filter.py
│   │   ├── layer2_application_gateway.py
│   │   ├── layer3_ids_ips.py
│   │   ├── layer4_threat_intelligence.py
│   │   ├── layer5_network_access_control.py
│   │   └── layer6_siem_integration.py
│   ├── ml/                     # Machine learning
│   │   └── threat_detection.py
│   └── web/                    # Web interface
│       ├── dashboard.py        # Flask application
│       └── templates/          # HTML templates
├── config/                     # Configuration files
├── tests/                      # Test suite
├── docs/                       # Documentation
├── scripts/                    # Deployment scripts
└── logs/                       # Log files
```

### Core Components

#### FirewallEngine (`src/core/firewall_engine.py`)

The main orchestrator that coordinates all security layers:

```python
class FirewallEngine:
    def __init__(self, config_path: str):
        self.config_manager = ConfigManager(config_path)
        self.logger = SecurityLogger()
        self.layers = self._initialize_layers()
        self.ml_engine = ThreatDetectionML()
    
    async def process_packet(self, packet_data: dict) -> dict:
        """Process packet through all enabled layers"""
        result = {"action": "allow", "layer": None, "reason": None}
        
        for layer in self.layers:
            if layer.is_enabled():
                layer_result = await layer.process(packet_data)
                if layer_result["action"] == "block":
                    result = layer_result
                    break
        
        # Log the result
        await self.logger.log_event(result)
        return result
```

#### Configuration Manager (`src/core/config_manager.py`)

Centralized configuration handling:

```python
class ConfigManager:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
    
    def get(self, key: str, default=None):
        """Get configuration value using dot notation"""
        keys = key.split('.')
        value = self.config
        for k in keys:
            value = value.get(k, {})
            if not isinstance(value, dict):
                return value
        return default
    
    def update(self, key: str, value):
        """Update configuration value"""
        keys = key.split('.')
        config = self.config
        for k in keys[:-1]:
            config = config.setdefault(k, {})
        config[keys[-1]] = value
        self._save_config()
```

## API Development

### Creating New Endpoints

1. **Add Route to Dashboard**:
   ```python
   @app.route('/api/new-endpoint', methods=['GET', 'POST'])
   @login_required
   def new_endpoint():
       try:
           if request.method == 'POST':
               data = request.get_json()
               # Process data
               result = process_new_endpoint_data(data)
               return jsonify({"success": True, "data": result})
           else:
               # Return GET data
               return jsonify({"data": get_new_endpoint_data()})
       except Exception as e:
           return jsonify({"success": False, "error": str(e)}), 500
   ```

2. **Add Validation**:
   ```python
   from marshmallow import Schema, fields, ValidationError
   
   class NewEndpointSchema(Schema):
       name = fields.Str(required=True)
       type = fields.Str(required=True)
       enabled = fields.Bool(missing=True)
   
   @app.route('/api/new-endpoint', methods=['POST'])
   @login_required
   def new_endpoint():
       schema = NewEndpointSchema()
       try:
           data = schema.load(request.get_json())
           # Process validated data
       except ValidationError as err:
           return jsonify({"success": False, "errors": err.messages}), 400
   ```

3. **Add Documentation**:
   ```python
   """
   New Endpoint API
   
   GET /api/new-endpoint
   Returns list of items
   
   Response:
   {
       "data": [
           {
               "id": "item-1",
               "name": "Item Name",
               "type": "item_type"
           }
       ]
   }
   
   POST /api/new-endpoint
   Creates new item
   
   Request:
   {
       "name": "Item Name",
       "type": "item_type",
       "enabled": true
   }
   
   Response:
   {
       "success": true,
       "data": {
           "id": "new-item-id"
       }
   }
   """
   ```

### WebSocket Events

For real-time updates:

```python
@socketio.on('subscribe_to_events')
@login_required
def handle_event_subscription():
    """Subscribe client to real-time events"""
    join_room('events')
    emit('subscription_confirmed', {'room': 'events'})

def broadcast_event(event_data):
    """Broadcast event to all subscribed clients"""
    socketio.emit('new_event', event_data, room='events')
```

## Security Layer Development

### Creating a New Security Layer

1. **Layer Base Class**:
   ```python
   from abc import ABC, abstractmethod
   
   class SecurityLayer(ABC):
       def __init__(self, config: dict, logger):
           self.config = config
           self.logger = logger
           self.enabled = config.get('enabled', True)
           self.stats = {"processed": 0, "blocked": 0, "allowed": 0}
       
       @abstractmethod
       async def process(self, packet_data: dict) -> dict:
           """Process packet and return action"""
           pass
       
       def is_enabled(self) -> bool:
           return self.enabled
       
       def get_stats(self) -> dict:
           return self.stats.copy()
   ```

2. **Implement New Layer**:
   ```python
   class CustomSecurityLayer(SecurityLayer):
       def __init__(self, config: dict, logger):
           super().__init__(config, logger)
           self.custom_rules = config.get('custom_rules', [])
       
       async def process(self, packet_data: dict) -> dict:
           self.stats["processed"] += 1
           
           # Custom processing logic
           if self._should_block(packet_data):
               self.stats["blocked"] += 1
               return {
                   "action": "block",
                   "layer": "custom",
                   "reason": "Custom rule violation"
               }
           
           self.stats["allowed"] += 1
           return {"action": "allow", "layer": "custom"}
       
       def _should_block(self, packet_data: dict) -> bool:
           # Implement custom blocking logic
           for rule in self.custom_rules:
               if self._matches_rule(packet_data, rule):
                   return True
           return False
   ```

3. **Register Layer**:
   ```python
   # In firewall_engine.py
   def _initialize_layers(self) -> List[SecurityLayer]:
       layers = []
       
       # Add existing layers...
       
       # Add custom layer
       if self.config_manager.get('layers.custom.enabled', False):
           custom_config = self.config_manager.get('layers.custom', {})
           layers.append(CustomSecurityLayer(custom_config, self.logger))
       
       return layers
   ```

### Layer Configuration

Add layer configuration to `config/firewall.json`:

```json
{
  "layers": {
    "custom": {
      "enabled": true,
      "custom_rules": [
        {
          "name": "Block suspicious IPs",
          "condition": {"source_ip": "suspicious_range"},
          "action": "block"
        }
      ]
    }
  }
}
```

## Machine Learning Integration

### Adding New ML Models

1. **Model Base Class**:
   ```python
   from abc import ABC, abstractmethod
   import joblib
   
   class MLModel(ABC):
       def __init__(self, model_path: str = None):
           self.model = None
           if model_path:
               self.load_model(model_path)
       
       @abstractmethod
       def train(self, training_data):
           """Train the model"""
           pass
       
       @abstractmethod
       def predict(self, data) -> dict:
           """Make prediction"""
           pass
       
       def save_model(self, path: str):
           """Save trained model"""
           joblib.dump(self.model, path)
       
       def load_model(self, path: str):
           """Load trained model"""
           self.model = joblib.load(path)
   ```

2. **Implement Custom Model**:
   ```python
   from sklearn.ensemble import RandomForestClassifier
   from sklearn.preprocessing import StandardScaler
   
   class CustomThreatModel(MLModel):
       def __init__(self, model_path: str = None):
           super().__init__(model_path)
           self.scaler = StandardScaler()
           if not self.model:
               self.model = RandomForestClassifier(n_estimators=100)
       
       def train(self, training_data):
           X, y = self._prepare_data(training_data)
           X_scaled = self.scaler.fit_transform(X)
           self.model.fit(X_scaled, y)
       
       def predict(self, data) -> dict:
           features = self._extract_features(data)
           features_scaled = self.scaler.transform([features])
           prediction = self.model.predict_proba(features_scaled)[0]
           
           return {
               "threat_probability": prediction[1],
               "is_threat": prediction[1] > 0.5,
               "confidence": max(prediction)
           }
   ```

3. **Integration with Threat Detection**:
   ```python
   # In threat_detection.py
   class ThreatDetectionML:
       def __init__(self):
           self.models = {
               "anomaly": AnomalyDetectionModel(),
               "custom": CustomThreatModel()
           }
       
       async def analyze_packet(self, packet_data: dict) -> dict:
           results = {}
           for model_name, model in self.models.items():
               results[model_name] = model.predict(packet_data)
           
           # Combine results
           return self._combine_predictions(results)
   ```

## Web Interface Development

### Adding New Pages

1. **Create HTML Template**:
   ```html
   <!-- templates/new_page.html -->
   {% extends "base.html" %}
   
   {% block title %}New Page - ZehraShield{% endblock %}
   
   {% block content %}
   <div class="container-fluid">
       <h2>New Page</h2>
       <div id="newPageContent">
           <!-- Page content -->
       </div>
   </div>
   
   <script>
   // Page-specific JavaScript
   function loadNewPageData() {
       fetch('/api/new-page-data')
           .then(response => response.json())
           .then(data => {
               // Update page content
           });
   }
   
   document.addEventListener('DOMContentLoaded', loadNewPageData);
   </script>
   {% endblock %}
   ```

2. **Add Route**:
   ```python
   @app.route('/new-page')
   @login_required
   def new_page():
       return render_template('new_page.html')
   ```

3. **Update Navigation**:
   ```html
   <!-- In base.html -->
   <li class="nav-item">
       <a class="nav-link" href="/new-page">
           <i class="fas fa-new-icon"></i> New Page
       </a>
   </li>
   ```

### Frontend JavaScript Patterns

1. **API Calls**:
   ```javascript
   async function apiCall(endpoint, method = 'GET', data = null) {
       try {
           const options = {
               method: method,
               headers: {
                   'Content-Type': 'application/json'
               }
           };
           
           if (data) {
               options.body = JSON.stringify(data);
           }
           
           const response = await fetch(endpoint, options);
           const result = await response.json();
           
           if (!response.ok) {
               throw new Error(result.error || 'API call failed');
           }
           
           return result;
       } catch (error) {
           console.error('API Error:', error);
           showAlert(error.message, 'danger');
           throw error;
       }
   }
   ```

2. **Real-time Updates**:
   ```javascript
   // WebSocket connection
   const socket = io();
   
   socket.on('connect', function() {
       console.log('Connected to server');
       socket.emit('subscribe_to_events');
   });
   
   socket.on('new_event', function(data) {
       updateEventDisplay(data);
   });
   
   function updateEventDisplay(event) {
       // Update UI with new event
   }
   ```

## Testing

### Unit Tests

1. **Test Structure**:
   ```python
   # tests/test_security_layer.py
   import pytest
   from unittest.mock import Mock, AsyncMock
   from src.layers.layer1_packet_filter import PacketFilter
   
   class TestPacketFilter:
       @pytest.fixture
       def packet_filter(self):
           config = {"enabled": True, "mode": "block"}
           logger = Mock()
           return PacketFilter(config, logger)
       
       @pytest.mark.asyncio
       async def test_process_allowed_packet(self, packet_filter):
           packet_data = {
               "source_ip": "192.168.1.100",
               "destination_ip": "8.8.8.8",
               "protocol": "TCP"
           }
           
           result = await packet_filter.process(packet_data)
           assert result["action"] == "allow"
       
       @pytest.mark.asyncio
       async def test_process_blocked_packet(self, packet_filter):
           packet_data = {
               "source_ip": "1.2.3.4",  # Blocked IP
               "destination_ip": "8.8.8.8",
               "protocol": "TCP"
           }
           
           result = await packet_filter.process(packet_data)
           assert result["action"] == "block"
   ```

2. **Integration Tests**:
   ```python
   # tests/test_integration.py
   import pytest
   from src.core.firewall_engine import FirewallEngine
   
   class TestFirewallIntegration:
       @pytest.fixture
       def firewall_engine(self, tmp_path):
           config_file = tmp_path / "test_config.json"
           config_file.write_text('{"layers": {"layer1": {"enabled": true}}}')
           return FirewallEngine(str(config_file))
       
       @pytest.mark.asyncio
       async def test_full_packet_processing(self, firewall_engine):
           packet_data = {"source_ip": "192.168.1.100"}
           result = await firewall_engine.process_packet(packet_data)
           assert "action" in result
   ```

3. **API Tests**:
   ```python
   # tests/test_api.py
   import pytest
   from src.web.dashboard import create_app
   
   @pytest.fixture
   def client():
       app = create_app(testing=True)
       with app.test_client() as client:
           yield client
   
   def test_api_endpoint(client):
       response = client.get('/api/stats')
       assert response.status_code == 200
       data = response.get_json()
       assert "success" in data
   ```

### Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src/ --cov-report=html

# Run specific test file
python -m pytest tests/test_security_layer.py -v

# Run tests matching pattern
python -m pytest tests/ -k "test_packet" -v
```

## Deployment

### Development Deployment

```bash
# Install in development mode
pip install -e .

# Run with debugging
python main.py --debug --config config/firewall.json
```

### Production Deployment

1. **Use Deployment Script**:
   ```bash
   sudo ./scripts/deploy.sh
   ```

2. **Manual Deployment**:
   ```bash
   # Install as service
   sudo ./scripts/install.sh
   
   # Start service
   sudo systemctl start zehrashield
   sudo systemctl enable zehrashield
   ```

### Docker Deployment

1. **Create Dockerfile**:
   ```dockerfile
   FROM python:3.9-slim
   
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install -r requirements.txt
   
   COPY . .
   EXPOSE 8443
   
   CMD ["python", "main.py", "--config", "config/firewall.json"]
   ```

2. **Build and Run**:
   ```bash
   docker build -t zehrashield .
   docker run -d -p 8443:8443 --name zehrashield zehrashield
   ```

## Contributing

### Code Standards

1. **Python Style**: Follow PEP 8
2. **Type Hints**: Use type hints for all functions
3. **Documentation**: Docstrings for all classes and functions
4. **Testing**: Unit tests for all new functionality

### Commit Guidelines

1. **Format**: `type(scope): description`
2. **Types**: feat, fix, docs, style, refactor, test, chore
3. **Examples**:
   - `feat(layer1): add geo-blocking support`
   - `fix(api): resolve authentication issue`
   - `docs(readme): update installation instructions`

### Pull Request Process

1. **Create Feature Branch**: `git checkout -b feature/description`
2. **Implement Changes**: Follow code standards
3. **Add Tests**: Ensure test coverage
4. **Update Documentation**: Update relevant docs
5. **Submit PR**: Include detailed description
6. **Code Review**: Address reviewer feedback
7. **Merge**: Squash and merge when approved

### Development Guidelines

1. **Security First**: Always consider security implications
2. **Performance**: Profile code for performance bottlenecks
3. **Logging**: Add appropriate logging for debugging
4. **Error Handling**: Implement comprehensive error handling
5. **Documentation**: Keep documentation up to date

For questions or support, contact the development team at dev@zehrasec.com.
