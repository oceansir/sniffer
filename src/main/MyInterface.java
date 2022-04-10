package main;

import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.util.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import jpcap.NetworkInterface;
import jpcap.packet.Packet;

public class MyInterface extends JFrame{
	
	JMenuBar menubar;   //菜单条
	JMenu menuFile1,menuFile2; //菜单
	JMenuItem[] item;   //菜单项
	JMenuItem pro1,pro2,pro3;
	JTextField searchText;
	JButton sipButton,dipButton;
//	searchButton;
	JPanel panel;  
	JScrollPane scrollPane;  
	JTable table;  
	final String[] head = new String[] {
		"time","source ip", "dest ip", "protocol", "packet length"
	};
	NetworkInterface[] devices;
	Object[][] datalist = {};
	// packet view list
	DefaultTableModel tableModel;
	// packet list
	PacketCapture allpackets;
	
	public MyInterface(){
		allpackets = new PacketCapture();
		this.setTitle("Sniffer");
		this.setBounds(650, 150, 1200, 1000);
		menubar = new JMenuBar();
		build();   
	}

	public void build() {
		networkMenu(); 
		protocolMenu();
		
		sourceIpButton();
		destIpButton();
		
//		searchButton(); 
		
		setJMenuBar(menubar);
		
		packetListTable();  
		detailInforJframe();
		

		setResizable(false);
		setVisible(true);
		addWindowListener(new WindowAdapter() {  
			public void windowClosing(WindowEvent e) {  
				System.exit(0);
			}  

		});
	}

	public void detailInforJframe() {
		table.addMouseListener(new MouseAdapter(){
			public void mouseClicked(MouseEvent ev){
				if(ev.getClickCount() == 2){
					int row = table.getSelectedRow();
					
					// 详细信息
					JFrame frame = new JFrame("detail info");
					JPanel panel = new JPanel();
					final JTextArea info = new JTextArea(23, 42);
					info.setEditable(false);
					info.setLineWrap(true);
					info.setWrapStyleWord(true);
					frame.add(panel);
					panel.add(new JScrollPane(info));
//					JButton save = new JButton("保存到本地");
//					save.addActionListener(  
//						new ActionListener(){  
//							public void actionPerformed(ActionEvent e3) {  
//								String text = info.getText();
//								int name = (int)System.currentTimeMillis();
//								try {  
//									FileOutputStream fos = new FileOutputStream("d://"+name+".txt");   
//									fos.write(text.getBytes());  
//									fos.close();  
//								} catch (Exception e) {   
//									e.printStackTrace();  
//								} 
//							}  
//						}); 
//					panel.add(save);
					frame.setBounds(150, 150, 500, 500);
					frame.setVisible(true);
					frame.setResizable(false);
					ArrayList<Packet> packetlist = allpackets.getpacketlist();
					Map<String,String> hm1 = new HashMap<String,String>();
					Map<String,String> hm2 = new HashMap<String,String>();
					Packet packet = packetlist.get(row);
					
					info.append("IP头信息：\n");
					hm1 = new PacketAnalyze(packet).IPanalyze();
					for(Map.Entry<String,String> me1 : hm1.entrySet()){
						info.append(me1.getKey()+" : "+me1.getValue()+"\n");
						System.out.println(me1.getValue());
					}
					hm2 = new PacketAnalyze(packet).packetClass();
					info.append("\n" + hm2.get("协议")+"\n");
					for(Map.Entry<String,String> me : hm2.entrySet()) {
						info.append(me.getKey()+" : "+me.getValue()+"\n");
					}
				}
			}
		});
	}
	

	public void packetListTable() {
		// packet view list
		tableModel = new DefaultTableModel(datalist, head);
		table = new JTable(tableModel){
			public boolean isCellEditable(int row, int column){
				return false;
			}
		};
		allpackets.setTable(tableModel);	
		table.setPreferredScrollableViewportSize(new Dimension(500, 60));// 设置表格的大小 
		table.setRowHeight(30);// 设置每行的高度为20
		table.setRowMargin(5);// 设置相邻两行单元格的距离  
		table.setRowSelectionAllowed(true);// 设置可否被选择.默认为false  
		table.setSelectionBackground(Color.cyan);// 设置所选择行的背景色  
		table.setSelectionForeground(Color.red);// 设置所选择行的前景色  
		table.setShowGrid(true);// 是否显示网格线   
		table.doLayout();   
		scrollPane = new JScrollPane(table); 
		panel = new JPanel(new GridLayout(0, 1));  
		panel.setPreferredSize(new Dimension(600, 300));  
		panel.setBackground(Color.black);  
		panel.add(scrollPane); 
		
		
		
		setContentPane(panel);  
		
		
		pack();
	}

//	public void searchButton() {
//		//根据关键字进行过滤
//		searchButton = new JButton(" search  ");
//		searchButton.addActionListener(  
//			new ActionListener(){  
//				public void actionPerformed(ActionEvent e) {  
//					String fkeyword = JOptionPane.showInputDialog("Please enter the data keyword to filter packets:");    
//					allpackets.setFilter("keyword "+fkeyword);
//					allpackets.clearpackets();
//					while(tableModel.getRowCount()>0){
//						tableModel.removeRow(tableModel.getRowCount()-1);
//					}
//				}  
//			});
//		//将菜单添加到菜单条上
//		menubar.add(searchButton);
//	}

	public void destIpButton() {
		//根据目的IP进行过滤
		dipButton = new JButton(" dest ip ");
		dipButton.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e) {  
					String fdip = JOptionPane.showInputDialog("Please enter the destination IP address to filter packets:");  
					allpackets.setFilter("dip "+fdip);
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			});
		menubar.add(dipButton);
	}

	public void sourceIpButton() {
		//根据源IP进行过滤
		sipButton = new JButton(" source ip ");
		sipButton.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e) {  
					String fsip = JOptionPane.showInputDialog("Please enter the source IP address to filter packets:");  
					allpackets.setFilter("sip "+fsip);
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			});
		menubar.add(sipButton);
	}

	public void protocolMenu() {
		//根据协议进行过滤
		menuFile2 = new JMenu("  protocol  ");
		pro1 = new JMenuItem("ICMP");
		pro2 = new JMenuItem("TCP");
		pro3 = new JMenuItem("UDP");
		pro1.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e3) {  
					allpackets.setFilter("ICMP");
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			}); 
		pro2.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e3) {  
					allpackets.setFilter("TCP");
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			});
		pro3.addActionListener(  
			new ActionListener(){  
				public void actionPerformed(ActionEvent e3) {  
					allpackets.setFilter("UDP");
					allpackets.clearpackets();
					while(tableModel.getRowCount()>0){
						tableModel.removeRow(tableModel.getRowCount()-1);
					}
				}  
			}); 
		menuFile2.add(pro1);
		menuFile2.add(pro2);
		menuFile2.add(pro3);
		
		menubar.add(menuFile2);
	}

	public void networkMenu() {
		//根据网卡进行过滤
		menuFile1 = new JMenu(" network card ");
		NetworkInterface[] devices = new NetworkCard().getDevices();
		item = new JMenuItem[devices.length];
		for (int i = 0; i < devices.length; i++) {
			item[i] = new JMenuItem(i + ": " + devices[i].name + "("
					+ devices[i].description  + ")");
			menuFile1.add(item[i]);
			item[i].addActionListener(new CardActionListener(devices[i]));
		}
		menubar.add(menuFile1);
	}

	private class CardActionListener implements ActionListener{

		NetworkInterface device;
		CardActionListener(NetworkInterface device){
			this.device = device;
		}
		public void actionPerformed(ActionEvent e) {
			allpackets.setDevice(device);
			allpackets.setFilter("");
			new Thread(allpackets).start();   //开启抓包线程
		}     
	}  
}