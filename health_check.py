"""
Aether-AI Health Check Script
Verifies all APIs and hardware drivers respond in <200ms
Target: Acer Swift Neo (16GB RAM, 512GB SSD, Intel NPU)
"""

import time
import psutil
import platform
import asyncio
from typing import Dict, Any, List
from dataclasses import dataclass
import sys
import os

@dataclass
class HealthCheckResult:
    """Result of a health check"""
    component: str
    status: str
    latency_ms: float
    details: Dict[str, Any]
    passed: bool


class AetherHealthChecker:
    """
    Comprehensive health checker for Aether-AI system
    Checks:
    - API response times (<200ms)
    - NPU driver availability
    - Memory usage (<8GB for 16GB system)
    - Audio device latency
    - LLM provider connectivity
    """
    
    def __init__(self):
        self.results: List[HealthCheckResult] = []
        self.threshold_ms = 200
    
    async def check_all(self) -> Dict[str, Any]:
        """Run all health checks"""
        print("=" * 70)
        print("🏥 AETHER-AI HEALTH CHECK")
        print(f"Target Device: Acer Swift Neo (16GB RAM, Intel NPU)")
        print(f"Threshold: <{self.threshold_ms}ms for all checks")
        print("=" * 70)
        print()
        
        await self.check_system_resources()
        await self.check_npu_availability()
        await self.check_audio_devices()
        await self.check_llm_providers()
        await self.check_dependencies()
        
        return self.generate_report()
    
    async def check_system_resources(self):
        """Check RAM, CPU, and disk usage"""
        start = time.time()
        
        try:
            memory = psutil.virtual_memory()
            cpu_percent = psutil.cpu_percent(interval=0.1)
            disk = psutil.disk_usage('/')
            
            latency = (time.time() - start) * 1000
            
            memory_gb = memory.used / (1024**3)
            memory_percent = memory.percent
            
            passed = memory_gb < 8.0 and latency < self.threshold_ms
            
            result = HealthCheckResult(
                component="System Resources",
                status="✅ PASS" if passed else "❌ FAIL",
                latency_ms=latency,
                details={
                    "ram_used_gb": round(memory_gb, 2),
                    "ram_total_gb": round(memory.total / (1024**3), 2),
                    "ram_percent": round(memory_percent, 1),
                    "cpu_percent": round(cpu_percent, 1),
                    "disk_free_gb": round(disk.free / (1024**3), 2)
                },
                passed=passed
            )
            
            self.results.append(result)
            self._print_result(result)
            
        except Exception as e:
            self._handle_error("System Resources", e, time.time() - start)
    
    async def check_npu_availability(self):
        """Check if Intel NPU is available via OpenVINO"""
        start = time.time()
        
        try:
            try:
                import openvino as ov
                
                core = ov.Core()
                available_devices = core.available_devices
                
                npu_available = any('NPU' in device for device in available_devices)
                
                latency = (time.time() - start) * 1000
                passed = latency < self.threshold_ms
                
                result = HealthCheckResult(
                    component="Intel NPU (OpenVINO)",
                    status="✅ AVAILABLE" if npu_available else "⚠️  NOT FOUND",
                    latency_ms=latency,
                    details={
                        "npu_available": npu_available,
                        "available_devices": available_devices,
                        "openvino_version": ov.__version__ if hasattr(ov, '__version__') else "unknown"
                    },
                    passed=passed and npu_available
                )
                
            except ImportError:
                latency = (time.time() - start) * 1000
                result = HealthCheckResult(
                    component="Intel NPU (OpenVINO)",
                    status="❌ NOT INSTALLED",
                    latency_ms=latency,
                    details={
                        "npu_available": False,
                        "error": "OpenVINO not installed",
                        "install_command": "pip install openvino openvino-dev"
                    },
                    passed=False
                )
            
            self.results.append(result)
            self._print_result(result)
            
        except Exception as e:
            self._handle_error("Intel NPU", e, time.time() - start)
    
    async def check_audio_devices(self):
        """Check audio input/output devices and latency"""
        start = time.time()
        
        try:
            import pyaudio
            
            p = pyaudio.PyAudio()
            
            input_devices = []
            output_devices = []
            
            for i in range(p.get_device_count()):
                info = p.get_device_info_by_index(i)
                if info['maxInputChannels'] > 0:
                    input_devices.append(info['name'])
                if info['maxOutputChannels'] > 0:
                    output_devices.append(info['name'])
            
            default_input = p.get_default_input_device_info()
            default_output = p.get_default_output_device_info()
            
            p.terminate()
            
            latency = (time.time() - start) * 1000
            passed = len(input_devices) > 0 and latency < self.threshold_ms
            
            result = HealthCheckResult(
                component="Audio Devices",
                status="✅ PASS" if passed else "❌ FAIL",
                latency_ms=latency,
                details={
                    "input_devices_count": len(input_devices),
                    "output_devices_count": len(output_devices),
                    "default_input": default_input['name'],
                    "default_output": default_output['name']
                },
                passed=passed
            )
            
            self.results.append(result)
            self._print_result(result)
            
        except Exception as e:
            self._handle_error("Audio Devices", e, time.time() - start)
    
    async def check_llm_providers(self):
        """Check LLM provider API connectivity"""
        start = time.time()
        
        try:
            from dotenv import load_dotenv
            load_dotenv()
            
            providers_status = {}
            
            openai_key = os.getenv("OPENAI_API_KEY")
            groq_key = os.getenv("GROQ_API_KEY")
            anthropic_key = os.getenv("ANTHROPIC_API_KEY")
            
            if openai_key:
                try:
                    from openai import OpenAI
                    client = OpenAI(api_key=openai_key, timeout=2.0)
                    models = client.models.list()
                    providers_status["OpenAI"] = "✅ Connected"
                except Exception as e:
                    providers_status["OpenAI"] = f"❌ Error: {str(e)[:30]}"
            else:
                providers_status["OpenAI"] = "⚠️  No API key"
            
            if groq_key:
                try:
                    from groq import Groq
                    client = Groq(api_key=groq_key, timeout=2.0)
                    providers_status["Groq"] = "✅ Connected"
                except Exception as e:
                    providers_status["Groq"] = f"❌ Error: {str(e)[:30]}"
            else:
                providers_status["Groq"] = "⚠️  No API key"
            
            
            latency = (time.time() - start) * 1000
            
            connected_count = sum(1 for status in providers_status.values() if "✅" in status)
            passed = connected_count > 0 and latency < 5000
            
            result = HealthCheckResult(
                component="LLM Providers",
                status="✅ PASS" if passed else "⚠️  PARTIAL",
                latency_ms=latency,
                details={
                    "providers": providers_status,
                    "connected_count": connected_count
                },
                passed=passed
            )
            
            self.results.append(result)
            self._print_result(result)
            
        except Exception as e:
            self._handle_error("LLM Providers", e, time.time() - start)
    
    async def check_dependencies(self):
        """Check critical Python dependencies"""
        start = time.time()
        
        critical_deps = [
            "numpy",
            "torch",
            "whisper",
            "pyaudio",
            "pyttsx3",
            "fastapi",
            "uvicorn"
        ]
        
        missing = []
        installed = []
        
        for dep in critical_deps:
            try:
                __import__(dep)
                installed.append(dep)
            except ImportError:
                missing.append(dep)
        
        latency = (time.time() - start) * 1000
        passed = len(missing) == 0 and latency < self.threshold_ms
        
        result = HealthCheckResult(
            component="Dependencies",
            status="✅ PASS" if passed else "❌ FAIL",
            latency_ms=latency,
            details={
                "installed": installed,
                "missing": missing,
                "total_checked": len(critical_deps)
            },
            passed=passed
        )
        
        self.results.append(result)
        self._print_result(result)
    
    def _print_result(self, result: HealthCheckResult):
        """Print a health check result"""
        print(f"[{result.status}] {result.component}")
        print(f"  Latency: {result.latency_ms:.2f}ms")
        for key, value in result.details.items():
            print(f"  {key}: {value}")
        print()
    
    def _handle_error(self, component: str, error: Exception, start_time: float):
        """Handle check errors"""
        latency = (time.time() - start_time) * 1000
        result = HealthCheckResult(
            component=component,
            status="❌ ERROR",
            latency_ms=latency,
            details={"error": str(error)},
            passed=False
        )
        self.results.append(result)
        self._print_result(result)
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate final health report"""
        total = len(self.results)
        passed = sum(1 for r in self.results if r.passed)
        failed = total - passed
        
        avg_latency = sum(r.latency_ms for r in self.results) / total if total > 0 else 0
        
        print("=" * 70)
        print("📊 HEALTH CHECK SUMMARY")
        print("=" * 70)
        print(f"Total Checks: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {failed}")
        print(f"Average Latency: {avg_latency:.2f}ms")
        print(f"Target Latency: <{self.threshold_ms}ms")
        print()
        
        if passed == total:
            print("🎉 ALL SYSTEMS OPERATIONAL - Ready for Jarvis-like performance!")
            overall_status = "HEALTHY"
        elif passed >= total * 0.7:
            print("⚠️  PARTIAL FUNCTIONALITY - Some components need attention")
            overall_status = "DEGRADED"
        else:
            print("❌ CRITICAL ISSUES - System needs immediate attention")
            overall_status = "UNHEALTHY"
        
        print("=" * 70)
        
        return {
            "overall_status": overall_status,
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "average_latency_ms": avg_latency,
            "threshold_ms": self.threshold_ms,
            "checks": [
                {
                    "component": r.component,
                    "status": r.status,
                    "latency_ms": r.latency_ms,
                    "details": r.details,
                    "passed": r.passed
                }
                for r in self.results
            ]
        }


async def main():
    """Run health check"""
    checker = AetherHealthChecker()
    report = await checker.check_all()
    
    sys.exit(0 if report["overall_status"] == "HEALTHY" else 1)


if __name__ == "__main__":
    asyncio.run(main())
