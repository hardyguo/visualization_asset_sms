<?php
defined('BASEPATH') OR exit('No direct script access allowed');
class Assetscan extends Controller {
	public function __construct() {
		parent::__construct();

	}
	public function index()
	{
		$data['cur_title'] = array('','','','','active','','','','','');

		$this->load->database();
		
		$this->load->view('header');
		$this->load->view('nav', $data);
		$this->load->view('sidebar_menu', $data);
		$this->load->view('scan', $data);
		$this->load->view('footer');
	}
	
}
