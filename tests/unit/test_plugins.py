import pytest
import asyncio
from src.core.plugins.registry import registry
from src.core.plugins.loader import loader
from src.core.plugins.sandbox import sandbox

@pytest.fixture(scope="module", autouse=True)
def load_plugins():
    # Load all plugins before running tests
    loader.load_all_plugins()

def test_registry_contains_example_plugins():
    plugins = registry.get_all_plugins()
    assert len(plugins) >= 3
    plugin_names = [p.config.name for p in plugins]
    assert "calculator" in plugin_names
    assert "web_search" in plugin_names
    assert "system_info" in plugin_names

@pytest.mark.asyncio
async def test_sandbox_calculator_success():
    # Test valid evaluation
    result = await sandbox.execute_isolated(
        "plugins.calculator", 
        "CalculatorPlugin", 
        {"expression": "10 + 20"}
    )
    assert result["status"] == "success"
    assert result["data"]["result"] == 30

@pytest.mark.asyncio
async def test_sandbox_calculator_error():
    # Test invalid evaluation (syntax error)
    result = await sandbox.execute_isolated(
        "plugins.calculator", 
        "CalculatorPlugin", 
        {"expression": "10 + / 20"}
    )
    assert result["status"] == "success" # the sandbox succeeded in returning the plugin's error response
    assert "error" in result["data"]

@pytest.mark.asyncio
async def test_sandbox_system_info():
    result = await sandbox.execute_isolated(
        "plugins.system_info", 
        "SystemInfoPlugin", 
        {}
    )
    assert result["status"] == "success"
    assert "os" in result["data"]
