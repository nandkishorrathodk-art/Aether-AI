use pyo3::prelude::*;
use crate::crypto;

#[pyfunction]
fn encrypt(key: &[u8], data: &[u8], nonce: &[u8]) -> PyResult<Vec<u8>> {
    let key_array: &[u8; 32] = key.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    let nonce_array: &[u8; 12] = nonce.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Nonce must be 12 bytes"))?;
    
    let encryptor = crypto::Encryptor::new(key_array);
    encryptor.encrypt(data, nonce_array).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn decrypt(key: &[u8], data: &[u8], nonce: &[u8]) -> PyResult<Vec<u8>> {
    let key_array: &[u8; 32] = key.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Key must be 32 bytes"))?;
    let nonce_array: &[u8; 12] = nonce.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Nonce must be 12 bytes"))?;
    
    let encryptor = crypto::Encryptor::new(key_array);
    encryptor.decrypt(data, nonce_array).map_err(|e| PyErr::new::<pyo3::exceptions::PyRuntimeError, _>(e.to_string()))
}

#[pyfunction]
fn hash_password(password: &str, salt: &[u8]) -> PyResult<Vec<u8>> {
    let hasher = crypto::PasswordHasher::new();
    let hash = hasher.hash_password(password, salt);
    Ok(hash.to_vec())
}

#[pyfunction]
fn verify_password(password: &str, salt: &[u8], expected_hash: &[u8]) -> PyResult<bool> {
    let hasher = crypto::PasswordHasher::new();
    let hash_array: &[u8; 32] = expected_hash.try_into().map_err(|_| PyErr::new::<pyo3::exceptions::PyValueError, _>("Hash must be 32 bytes"))?;
    Ok(hasher.verify_password(password, salt, hash_array))
}

#[pymodule]
fn aether_rust(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(hash_password, m)?)?;
    m.add_function(wrap_pyfunction!(verify_password, m)?)?;
    Ok(())
}
