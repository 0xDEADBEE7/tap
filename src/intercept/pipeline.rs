use crate::http::{Request, Response};

pub trait Interceptor: Send + Sync {
    fn on_request(&self, _request: &mut Request) {}
    fn on_response(&self, _response: &mut Response) {}
}

#[derive(Default)]
pub struct Pipeline {
    interceptors: Vec<Box<dyn Interceptor>>,
}

impl Pipeline {
    pub fn request(&self, request: &mut Request) {
        for interceptor in &self.interceptors {
            interceptor.on_request(request);
        }
    }
    pub fn response(&self, response: &mut Response) {
        for interceptor in &self.interceptors {
            interceptor.on_response(response);
        }
    }
}
