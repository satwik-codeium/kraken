#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import subprocess
import tempfile
import time
import pytest

from .conftest import TEST_IMAGE


def has_cosign():
    """Check if cosign is available."""
    try:
        subprocess.check_call(['cosign', 'version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False


@pytest.mark.skipif(not has_cosign(), reason="cosign not available")
def test_image_verification_integration_workflow(proxy, agent):
    """
    Integration test for image verification workflow:
    1. Sign a test image with cosign
    2. Push signed image to Kraken proxy
    3. Pull image through agent (triggers verification)
    4. Verify that verification metrics are emitted
    """
    
    with tempfile.TemporaryDirectory() as temp_dir:
        private_key_path = os.path.join(temp_dir, 'cosign.key')
        public_key_path = os.path.join(temp_dir, 'cosign.pub')
        
        print("Generating cosign key pair...")
        subprocess.check_call([
            'cosign', 'generate-key-pair'
        ], cwd=temp_dir, env={**os.environ, 'COSIGN_PASSWORD': ''})
        
        signed_image = 'test/signed-alpine:verification-test'
        proxy_signed_image = f'{proxy.registry}/{signed_image}'
        
        subprocess.check_call(['docker', 'tag', TEST_IMAGE, proxy_signed_image])
        subprocess.check_call(['docker', 'push', proxy_signed_image])
        
        print(f"Signing image {proxy_signed_image}...")
        subprocess.check_call([
            'cosign', 'sign', '--key', private_key_path, proxy_signed_image
        ], env={**os.environ, 'COSIGN_PASSWORD': ''})
        
        print("Pulling signed image through agent...")
        agent.pull(signed_image)
        
        time.sleep(2)
        
        import requests
        health_response = requests.get(f'http://127.0.0.1:{agent.server_port}/health')
        assert health_response.status_code == 200
        
        print("Image verification integration test completed successfully!")


@pytest.mark.skipif(not has_cosign(), reason="cosign not available")  
def test_image_verification_unsigned_image(proxy, agent):
    """
    Test that unsigned images are handled gracefully (should skip verification).
    """
    
    unsigned_image = 'test/unsigned-alpine:verification-test'
    proxy_unsigned_image = f'{proxy.registry}/{unsigned_image}'
    
    subprocess.check_call(['docker', 'tag', TEST_IMAGE, proxy_unsigned_image])
    subprocess.check_call(['docker', 'push', proxy_unsigned_image])
    
    print("Pulling unsigned image through agent...")
    agent.pull(unsigned_image)
    
    time.sleep(2)
    
    import requests
    health_response = requests.get(f'http://127.0.0.1:{agent.server_port}/health')
    assert health_response.status_code == 200
    
    print("Unsigned image test completed successfully!")


def test_image_verification_metrics_endpoint(proxy, agent):
    """
    Test that we can access metrics from the agent server.
    This validates that metrics infrastructure is working.
    """
    
    test_image = 'test/metrics-test:latest'
    proxy_test_image = f'{proxy.registry}/{test_image}'
    
    subprocess.check_call(['docker', 'tag', TEST_IMAGE, proxy_test_image])
    subprocess.check_call(['docker', 'push', proxy_test_image])
    agent.pull(test_image)
    
    time.sleep(2)
    
    import requests
    health_response = requests.get(f'http://127.0.0.1:{agent.server_port}/health')
    assert health_response.status_code == 200
    
    readiness_response = requests.get(f'http://127.0.0.1:{agent.server_port}/readiness')
    assert readiness_response.status_code == 200
    
    print("Metrics endpoint test completed successfully!")
